from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
import json
import uuid
import sqlite3
import hashlib
import jwt
from datetime import datetime, timedelta
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Depends
import sqlite3
import hashlib

app = FastAPI(title="SaaS Restaurante API - Fase 4")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "saas.db"

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Restaurantes (Usuarios Admin)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS restaurants (
            id TEXT PRIMARY KEY,
            name TEXT,
            username TEXT UNIQUE,
            password_hash TEXT,
            subscription_active BOOLEAN DEFAULT 0
        )
    ''')
    
    # Personal (Staff)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS staff (
            id TEXT PRIMARY KEY,
            restaurant_id TEXT,
            name TEXT,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT
        )
    ''')
    
    # Mesas
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tables (
            id TEXT PRIMARY KEY,
            restaurant_id TEXT,
            name TEXT
        )
    ''')
    
    # Menú
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS menu_items (
            id TEXT PRIMARY KEY,
            restaurant_id TEXT,
            name TEXT,
            price REAL,
            category TEXT
        )
    ''')
    
    # Órdenes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id TEXT PRIMARY KEY,
            restaurant_id TEXT,
            table_name TEXT,
            waiter_name TEXT,
            status TEXT,
            total_amount REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS order_items (
            id TEXT PRIMARY KEY,
            order_id TEXT,
            item_name TEXT,
            quantity INTEGER,
            price REAL,
            notes TEXT
        )
    ''')
    
    # Caja / Turnos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shifts (
            id TEXT PRIMARY KEY,
            restaurant_id TEXT,
            opened_by TEXT,
            status TEXT,
            opening_balance REAL,
            closing_balance REAL,
            opened_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            closed_at TIMESTAMP
        )
    ''')
    
    # Migración de DB: Añadir stock si no existe
    try:
        cursor.execute("ALTER TABLE menu_items ADD COLUMN stock INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    
    conn.commit()
    conn.close()

init_db()

# --- MODELOS PYDANTIC ---
class RegisterRequest(BaseModel):
    name: str
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class StaffCreate(BaseModel):
    name: str
    username: str
    password: str
    role: str

class TableCreate(BaseModel):
    name: str

class MenuItemCreate(BaseModel):
    name: str
    price: float
    category: str = "General"
    stock: int = 0

class StockUpdate(BaseModel):
    stock: int

class OrderItemInput(BaseModel):
    item_name: str
    quantity: int
    price: float
    notes: str = ""

class OrderCreate(BaseModel):
    restaurant_id: str
    table_name: str
    waiter_name: str
    items: List[OrderItemInput]

class ShiftOpen(BaseModel):
    opened_by: str
    opening_balance: float

class ShiftClose(BaseModel):
    closing_balance: float

# --- UTILIDADES Y SEGURIDAD JWT ---
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

SECRET_KEY = "super_secreto_restaurant_saas_pro_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 7
security = HTTPBearer()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

def verify_restaurant_access(restaurant_id: str, current_user: dict = Depends(get_current_user)):
    if current_user.get("restaurant_id") != restaurant_id:
        raise HTTPException(status_code=403, detail="No tienes acceso a este restaurante")
    return current_user

# --- WEBSOCKETS MANAGER ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, restaurant_id: str):
        await websocket.accept()
        if restaurant_id not in self.active_connections:
            self.active_connections[restaurant_id] = []
        self.active_connections[restaurant_id].append(websocket)

    def disconnect(self, websocket: WebSocket, restaurant_id: str):
        if restaurant_id in self.active_connections:
            self.active_connections[restaurant_id].remove(websocket)
            if not self.active_connections[restaurant_id]:
                del self.active_connections[restaurant_id]

    async def broadcast_to_restaurant(self, restaurant_id: str, message: dict):
        if restaurant_id in self.active_connections:
            for connection in self.active_connections[restaurant_id]:
                await connection.send_text(json.dumps(message))

manager = ConnectionManager()

# --- ENDPOINTS AUTH Y SUSCRIPCIÓN ---

@app.post("/api/register")
async def register(req: RegisterRequest):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM restaurants WHERE username = ?", (req.username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="El usuario de restaurante ya existe")
        
    rest_id = str(uuid.uuid4())
    hashed_pwd = hash_password(req.password)
    
    cursor.execute('''
        INSERT INTO restaurants (id, name, username, password_hash, subscription_active)
        VALUES (?, ?, ?, ?, ?)
    ''', (rest_id, req.name, req.username, hashed_pwd, False))
    conn.commit()
    conn.close()
    
    return {"success": True, "restaurant_id": rest_id, "message": "Restaurante registrado"}

@app.post("/api/login")
async def login(req: LoginRequest):
    conn = get_db()
    cursor = conn.cursor()
    hashed_pwd = hash_password(req.password)
    
    # 1. Buscar en Restaurants (Admin)
    cursor.execute("SELECT id, name, subscription_active FROM restaurants WHERE username = ? AND password_hash = ?", (req.username, hashed_pwd))
    rest_row = cursor.fetchone()
    
    if rest_row:
        conn.close()
        rest_dict = dict(rest_row)
        # if not rest_dict["subscription_active"]:
        #     return {
        #         "success": False, "needs_payment": True, "restaurant_id": rest_dict["id"],
        #         "message": "Suscripción inactiva"
        #     }
            
        token = create_access_token({"restaurant_id": rest_dict["id"], "role": "admin"})
        return {
            "success": True, "restaurant_id": rest_dict["id"], "restaurant_name": rest_dict["name"],
            "role": "admin", "token": token, "user_name": "Administrador"
        }
        
    # 2. Si no es admin, buscar en Staff
    cursor.execute("SELECT id, restaurant_id, name, role FROM staff WHERE username = ? AND password_hash = ?", (req.username, hashed_pwd))
    staff_row = cursor.fetchone()
    
    if staff_row:
        staff_dict = dict(staff_row)
        cursor.execute("SELECT name, subscription_active FROM restaurants WHERE id = ?", (staff_dict["restaurant_id"],))
        parent_rest = dict(cursor.fetchone())
        conn.close()
        
        # if not parent_rest["subscription_active"]:
        #      return {
        #         "success": False, "needs_payment": True, "restaurant_id": staff_dict["restaurant_id"],
        #         "message": "La suscripción de este restaurante está inactiva"
        #     }
            
        token = create_access_token({"restaurant_id": staff_dict["restaurant_id"], "role": staff_dict["role"]})
        return {
            "success": True, "restaurant_id": staff_dict["restaurant_id"], "restaurant_name": parent_rest["name"],
            "role": staff_dict["role"], "token": token, "user_name": staff_dict["name"]
        }

    conn.close()
    raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")

@app.post("/api/subscription/pay/{restaurant_id}")
async def pay_subscription(restaurant_id: str, current_user: dict = Depends(verify_restaurant_access)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE restaurants SET subscription_active = 1 WHERE id = ?", (restaurant_id,))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Suscripción activada"}

# --- STAFF ---
@app.get("/api/staff/{restaurant_id}")
async def get_staff(restaurant_id: str, current_user: dict = Depends(verify_restaurant_access)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, username, role FROM staff WHERE restaurant_id = ?", (restaurant_id,))
    staff = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return staff

@app.post("/api/staff/{restaurant_id}")
async def add_staff(restaurant_id: str, staff: StaffCreate, current_user: dict = Depends(verify_restaurant_access)):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM staff WHERE username = ?", (staff.username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Este nombre de usuario de personal ya existe")
        
    staff_id = str(uuid.uuid4())
    hashed_pwd = hash_password(staff.password)
    
    cursor.execute('''
        INSERT INTO staff (id, restaurant_id, name, username, password_hash, role)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (staff_id, restaurant_id, staff.name, staff.username, hashed_pwd, staff.role))
    conn.commit()
    conn.close()
    return {"success": True, "id": staff_id}

@app.delete("/api/staff/{staff_id}")
async def delete_staff(staff_id: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM staff WHERE id = ?", (staff_id,))
    conn.commit()
    conn.close()
    return {"success": True}

# --- MESAS ---
@app.get("/api/tables/{restaurant_id}")
async def get_tables(restaurant_id: str, current_user: dict = Depends(verify_restaurant_access)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tables WHERE restaurant_id = ?", (restaurant_id,))
    tables = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return tables

@app.get("/api/tables/{restaurant_id}/status")
async def get_tables_status(restaurant_id: str, current_user: dict = Depends(verify_restaurant_access)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM tables WHERE restaurant_id = ?", (restaurant_id,))
    tables = [dict(row) for row in cursor.fetchall()]
    
    for t in tables:
        cursor.execute("SELECT id FROM orders WHERE restaurant_id = ? AND table_name = ? AND status != 'completed'", (restaurant_id, t['name']))
        t['is_occupied'] = cursor.fetchone() is not None
        
    conn.close()
    return tables

@app.post("/api/tables/{restaurant_id}")
async def add_table(restaurant_id: str, table: TableCreate, current_user: dict = Depends(verify_restaurant_access)):
    conn = get_db()
    cursor = conn.cursor()
    table_id = str(uuid.uuid4())
    cursor.execute('''
        INSERT INTO tables (id, restaurant_id, name)
        VALUES (?, ?, ?)
    ''', (table_id, restaurant_id, table.name))
    conn.commit()
    conn.close()
    return {"success": True, "id": table_id}

@app.delete("/api/tables/{table_id}")
async def delete_table(table_id: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM tables WHERE id = ?", (table_id,))
    conn.commit()
    conn.close()
    return {"success": True}

# --- MENÚ ---
@app.get("/api/menu/{restaurant_id}")
async def get_menu(restaurant_id: str, current_user: dict = Depends(verify_restaurant_access)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM menu_items WHERE restaurant_id = ?", (restaurant_id,))
    items = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return items

@app.post("/api/menu/{restaurant_id}")
async def add_menu_item(restaurant_id: str, item: MenuItemCreate, current_user: dict = Depends(verify_restaurant_access)):
    conn = get_db()
    cursor = conn.cursor()
    item_id = str(uuid.uuid4())
    cursor.execute('''
        INSERT INTO menu_items (id, restaurant_id, name, price, category, stock)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (item_id, restaurant_id, item.name, item.price, item.category, item.stock))
    conn.commit()
    conn.close()
    return {"success": True, "id": item_id}

@app.delete("/api/menu/{item_id}")
async def delete_menu_item(item_id: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM menu_items WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()
    return {"success": True}

@app.put("/api/menu/{item_id}/stock")
async def update_stock(item_id: str, payload: StockUpdate):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE menu_items SET stock = ? WHERE id = ?", (payload.stock, item_id))
    conn.commit()
    conn.close()
    return {"success": True}

# --- ÓRDENES ---
@app.get("/api/orders/{restaurant_id}")
async def get_active_orders(restaurant_id: str, current_user: dict = Depends(verify_restaurant_access)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE restaurant_id = ? AND status != 'completed' ORDER BY created_at DESC", (restaurant_id,))
    orders_rows = cursor.fetchall()
    
    orders = []
    for row in orders_rows:
        order_dict = dict(row)
        cursor.execute("SELECT * FROM order_items WHERE order_id = ?", (order_dict["id"],))
        order_dict["items"] = [dict(i) for i in cursor.fetchall()]
        orders.append(order_dict)
        
    conn.close()
    return orders

@app.post("/api/orders")
async def create_order(order: OrderCreate):
    conn = get_db()
    cursor = conn.cursor()
    
    order_id = str(uuid.uuid4())
    total_amount = sum([item.quantity * item.price for item in order.items])
    
    cursor.execute('''
        INSERT INTO orders (id, restaurant_id, table_name, waiter_name, status, total_amount)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (order_id, order.restaurant_id, order.table_name, order.waiter_name, "pending", total_amount))
    
    for item in order.items:
        item_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO order_items (id, order_id, item_name, quantity, price, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (item_id, order_id, item.item_name, item.quantity, item.price, item.notes))
        
        # Descontar del inventario
        cursor.execute('''
            UPDATE menu_items SET stock = stock - ? 
            WHERE name = ? AND restaurant_id = ?
        ''', (item.quantity, item.item_name, order.restaurant_id))
    
    conn.commit()
    conn.close()
    
    order_data = order.model_dump()
    order_data["id"] = order_id
    order_data["status"] = "pending"
    order_data["total_amount"] = total_amount
    
    await manager.broadcast_to_restaurant(
        restaurant_id=order.restaurant_id,
        message={"type": "NEW_ORDER", "data": order_data}
    )
    
    return {"success": True, "order": order_data}

@app.put("/api/orders/{order_id}/ready")
async def mark_order_ready(order_id: str, restaurant_id: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE orders SET status = 'ready' WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()
    
    await manager.broadcast_to_restaurant(
        restaurant_id=restaurant_id,
        message={"type": "ORDER_UPDATED", "data": {"order_id": order_id, "status": "ready"}}
    )
    return {"success": True}

@app.put("/api/orders/{order_id}/completed")
async def mark_order_completed(order_id: str, restaurant_id: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE orders SET status = 'completed' WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()
    return {"success": True}

@app.websocket("/ws/kitchen/{restaurant_id}")
async def websocket_kitchen_endpoint(websocket: WebSocket, restaurant_id: str):
    await manager.connect(websocket, restaurant_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, restaurant_id)

# --- CAJA / SHIFTS ---
@app.get("/api/shifts/{restaurant_id}/current")
async def get_current_shift(restaurant_id: str, current_user: dict = Depends(verify_restaurant_access)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM shifts WHERE restaurant_id = ? AND status = 'open'", (restaurant_id,))
    row = cursor.fetchone()
    conn.close()
    if row: return {"success": True, "shift": dict(row)}
    return {"success": False, "shift": None}

@app.post("/api/shifts/{restaurant_id}/open")
async def open_shift(restaurant_id: str, shift: ShiftOpen, current_user: dict = Depends(verify_restaurant_access)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM shifts WHERE restaurant_id = ? AND status = 'open'", (restaurant_id,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Ya hay un turno abierto")
        
    shift_id = str(uuid.uuid4())
    cursor.execute('''
        INSERT INTO shifts (id, restaurant_id, opened_by, status, opening_balance)
        VALUES (?, ?, ?, ?, ?)
    ''', (shift_id, restaurant_id, shift.opened_by, "open", shift.opening_balance))
    conn.commit()
    conn.close()
    return {"success": True, "shift_id": shift_id}

@app.post("/api/shifts/{restaurant_id}/close/{shift_id}")
async def close_shift(restaurant_id: str, shift_id: str, shift: ShiftClose, current_user: dict = Depends(verify_restaurant_access)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE shifts SET status = 'closed', closing_balance = ?, closed_at = CURRENT_TIMESTAMP
        WHERE id = ? AND restaurant_id = ?
    ''', (shift.closing_balance, shift_id, restaurant_id))
    conn.commit()
    conn.close()
    return {"success": True}

# --- DASHBOARD ---
@app.get("/api/dashboard/{restaurant_id}")
async def get_dashboard(restaurant_id: str, current_user: dict = Depends(verify_restaurant_access)):
    conn = get_db()
    cursor = conn.cursor()
    
    # Ganancias del día (órdenes completadas o listas hoy)
    cursor.execute('''
        SELECT SUM(total_amount) as total_earnings, COUNT(id) as total_orders 
        FROM orders 
        WHERE restaurant_id = ? AND date(created_at) = date('now')
    ''', (restaurant_id,))
    today_stats = cursor.fetchone()
    
    total_earnings = today_stats["total_earnings"] or 0
    total_orders = today_stats["total_orders"] or 0
    average_ticket = total_earnings / total_orders if total_orders > 0 else 0
    
    # Platos Estrella (Top 3 vendidos hoy)
    cursor.execute('''
        SELECT oi.item_name, SUM(oi.quantity) as total_sold
        FROM order_items oi
        JOIN orders o ON oi.order_id = o.id
        WHERE o.restaurant_id = ? AND date(o.created_at) = date('now')
        GROUP BY oi.item_name
        ORDER BY total_sold DESC LIMIT 3
    ''', (restaurant_id,))
    top_items = [dict(row) for row in cursor.fetchall()]

    # Productos con bajo stock (menos de 10)
    cursor.execute('''
        SELECT name, stock FROM menu_items 
        WHERE restaurant_id = ? AND stock <= 10
    ''', (restaurant_id,))
    low_stock = [dict(row) for row in cursor.fetchall()]
    
    # Historial reciente
    cursor.execute('''
        SELECT id, table_name, total_amount, status 
        FROM orders 
        WHERE restaurant_id = ? 
        ORDER BY created_at DESC LIMIT 10
    ''', (restaurant_id,))
    recent_orders = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return {
        "success": True,
        "today_earnings": total_earnings,
        "today_orders": total_orders,
        "average_ticket": average_ticket,
        "top_items": top_items,
        "low_stock_items": low_stock,
        "recent_orders": recent_orders
    }
