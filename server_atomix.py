import socket
import threading
import json
import time
import hashlib
import os
from decimal import Decimal, getcontext
from math import floor
from flask import Flask, jsonify

getcontext().prec = 10

BLOCKCHAIN_FILE = "blockchain_server.json"
USERS_FILE = "users_server.json"

lock = threading.Lock()

class ConnectionManager:
    def __init__(self):
        # Diccionario ip -> {"usuario": username, "slots_usados": int, "last_active": timestamp}
        self.connections = {}
        self.lock = threading.Lock()

    def add_connection(self, ip, username, slots):
        with self.lock:
            if ip not in self.connections:
                self.connections[ip] = {"usuario": username, "slots_usados": slots, "last_active": time.time()}
                return True, ""
            else:
                data = self.connections[ip]
                if data["usuario"] == username:
                    data["slots_usados"] = slots
                    data["last_active"] = time.time()
                    return True, ""
                else:
                    return False, "Esta IP ya está registrada para otro usuario."

    def remove_connection(self, ip, username):
        with self.lock:
            if ip in self.connections and self.connections[ip]["usuario"] == username:
                del self.connections[ip]

    def count_miners(self):
        now = time.time()
        with self.lock:
            to_delete = []
            for ip, data in self.connections.items():
                if now - data["last_active"] > 600:  # 10 minutos inactivo
                    to_delete.append(ip)
            for ip in to_delete:
                del self.connections[ip]
            return len(self.connections)

    def get_connections(self):
        with self.lock:
            return self.connections.copy()

def decimal_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError

class Block:
    def __init__(self, index, timestamp, data, previous_hash, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = (str(self.index) + str(self.timestamp) +
                        json.dumps(self.data, sort_keys=True) +
                        self.previous_hash + str(self.nonce))
        return hashlib.sha256(block_string.encode()).hexdigest()

class Blockchain:
    def __init__(self, difficulty=4):
        self.chain = []
        self.difficulty = difficulty
        self.load_chain()

    def load_chain(self):
        if os.path.exists(BLOCKCHAIN_FILE):
            with open(BLOCKCHAIN_FILE, "r") as f:
                chain_data = json.load(f)
                self.chain = []
                for block_data in chain_data:
                    block = Block(block_data['index'], block_data['timestamp'], block_data['data'],
                                  block_data['previous_hash'], block_data['nonce'])
                    block.hash = block_data['hash']
                    self.chain.append(block)
        else:
            # Crear bloque génesis
            genesis_block = Block(0, time.time(), {"mensaje": "Bloque génesis"}, "0")
            genesis_block.hash = genesis_block.compute_hash()
            self.chain = [genesis_block]
            self.save_chain()

    def save_chain(self):
        chain_data = []
        for block in self.chain:
            chain_data.append({
                "index": block.index,
                "timestamp": block.timestamp,
                "data": block.data,
                "previous_hash": block.previous_hash,
                "nonce": block.nonce,
                "hash": block.hash
            })
        with open(BLOCKCHAIN_FILE, "w") as f:
            json.dump(chain_data, f, indent=4, default=decimal_default)

    def last_block(self):
        if self.chain:
            return self.chain[-1]
        return None

    def add_block(self, block):
        if self.is_valid_block(block, self.last_block()):
            self.chain.append(block)
            self.save_chain()
            return True
        return False

    def is_valid_block(self, block, prev_block):
        if prev_block is None and block.index == 0:
            return True
        if prev_block is None:
            return False
        if prev_block.index + 1 != block.index:
            return False
        if prev_block.hash != block.previous_hash:
            return False
        if block.compute_hash() != block.hash:
            return False
        if not block.hash.startswith("0" * self.difficulty):
            return False
        return True

class UserManager:
    def __init__(self):
        self.users = {}
        self.load_users()

    def load_users(self):
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, "r") as f:
                raw = json.load(f)
                for u, d in raw.items():
                    d['balance'] = Decimal(str(d['balance']))
                    d['mining_power'] = Decimal(str(d['mining_power']))
                self.users = raw
        else:
            self.users = {}

    def save_users(self):
        serializable = {}
        for u, d in self.users.items():
            serializable[u] = {
                "pin_hash": d["pin_hash"],
                "balance": float(d["balance"]),
                "mining_power": float(d["mining_power"]),
                "slots": d.get("slots", 1),
                "mining_time": d.get("mining_time", 0),
                "last_active": d.get("last_active", time.time())
            }
        with open(USERS_FILE, "w") as f:
            json.dump(serializable, f, indent=4)

    def hash_pin(self, pin):
        return hashlib.sha256(pin.encode()).hexdigest()

    def register_user(self, username, pin):
        with lock:
            if username in self.users:
                return False, "Usuario ya existe"
            self.users[username] = {
                "pin_hash": self.hash_pin(pin),
                "balance": Decimal("0.0"),
                "mining_power": Decimal("1.0"),
                "slots": 1,
                "mining_time": 0,
                "last_active": time.time()
            }
            self.save_users()
            return True, "Usuario registrado"

    def authenticate(self, username, pin):
        with lock:
            if username not in self.users:
                return False
            return self.users[username]["pin_hash"] == self.hash_pin(pin)

    def get_user_data(self, username):
        with lock:
            return self.users.get(username)

    def update_user(self, username, data):
        with lock:
            if username in self.users:
                self.users[username].update(data)
                self.users[username]['last_active'] = time.time()
                mining_power = Decimal(str(self.users[username].get("mining_power", 1)))
                self.users[username]['slots'] = max(1, floor(mining_power))
                self.save_users()
                return self.users[username]['slots'], self.users[username]['mining_power'], self.users[username]['balance']

    def burn_coins(self, username, amount):
        with lock:
            user = self.users.get(username)
            if user is None:
                return False, "Usuario no encontrado"
            amount = Decimal(amount)
            if user["balance"] < amount:
                return False, "Saldo insuficiente"
            user["balance"] -= amount
            increment = amount / Decimal("1000")
            user["mining_power"] += increment
            user["slots"] = max(1, floor(user["mining_power"]))
            self.save_users()
            return True, f"Poder minero aumentado en {increment:.3f}, ahora tienes {user['slots']} slots"

class ClientHandler(threading.Thread):
    def __init__(self, conn, addr, blockchain, user_manager, conn_manager):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.blockchain = blockchain
        self.user_manager = user_manager
        self.conn_manager = conn_manager

    def run(self):
        ip = self.addr[0]
        username = ""
        try:
            data = self.conn.recv(65536).decode()
            msg = json.loads(data)
            mtype = msg.get("type")

            if mtype == "request_chain":
                chain_data = []
                for b in self.blockchain.chain:
                    chain_data.append({
                        "index": b.index,
                        "timestamp": b.timestamp,
                        "data": b.data,
                        "previous_hash": b.previous_hash,
                        "nonce": b.nonce,
                        "hash": b.hash
                    })
                self.conn.send(json.dumps({"type": "chain_response", "chain": chain_data}).encode())

            elif mtype == "new_block":
                block_data = msg.get("block")
                block = Block(block_data['index'], block_data['timestamp'], block_data['data'],
                              block_data['previous_hash'], block_data['nonce'])
                block.hash = block_data['hash']

                username = block.data.get("usuario")
                reward = Decimal(str(block.data.get("recompensa", "0")))

                if self.blockchain.add_block(block):
                    user_data = self.user_manager.get_user_data(username)
                    if user_data:
                        user_data["balance"] += reward
                        user_data["mining_time"] += 1
                        slots, mining_power, balance = self.user_manager.update_user(username, user_data)
                        self.conn_manager.add_connection(ip, username, slots)
                    self.conn.send(json.dumps({"type": "block_accepted", "index": block.index}).encode())
                    print(f"[Servidor] Bloque #{block.index} aceptado de {ip} usuario {username}")
                else:
                    self.conn.send(json.dumps({"type": "block_rejected", "index": block.index}).encode())
                    print(f"[Servidor] Bloque #{block.index} rechazado de {ip} usuario {username}")

            elif mtype == "register":
                username = msg.get("username")
                pin = msg.get("pin")
                ok, msg_resp = self.user_manager.register_user(username, pin)
                self.conn.send(json.dumps({"type": "register_response", "ok": ok, "message": msg_resp}).encode())

            elif mtype == "login":
                username = msg.get("username")
                pin = msg.get("pin")
                if self.user_manager.authenticate(username, pin):
                    user_data = self.user_manager.get_user_data(username)
                    slots = max(1, floor(user_data["mining_power"]))
                    ok_ip, msg_ip = self.conn_manager.add_connection(ip, username, slots)
                    if not ok_ip:
                        response = {"type": "login_response", "ok": False, "message": msg_ip}
                    else:
                        response = {
                            "type": "login_response",
                            "ok": True,
                            "balance": float(user_data["balance"]),
                            "mining_power": float(user_data["mining_power"]),
                            "slots": slots,
                            "miners_online": self.conn_manager.count_miners()
                        }
                else:
                    response = {"type": "login_response", "ok": False, "message": "Credenciales incorrectas"}
                self.conn.send(json.dumps(response).encode())

            elif mtype == "burn":
                username = msg.get("username")
                amount = msg.get("amount")
                ok, msg_resp = self.user_manager.burn_coins(username, amount)
                self.conn.send(json.dumps({"type": "burn_response", "ok": ok, "message": msg_resp}).encode())

            elif mtype == "get_miners_online":
                count = self.conn_manager.count_miners()
                self.conn.send(json.dumps({"type": "miners_online", "count": count}).encode())

            else:
                self.conn.send(json.dumps({"type": "error", "message": "Accion desconocida"}).encode())

        except Exception as e:
            print(f"[Servidor] Error con cliente {ip}: {e}")
        finally:
            self.conn_manager.remove_connection(ip, username)
            self.conn.close()

app = Flask(__name__)

blockchain = None
user_manager = None
conn_manager = None

@app.route("/health")
def health():
    return jsonify({
        "status": "running",
        "blocks": len(blockchain.chain) if blockchain else 0,
        "users": len(user_manager.users) if user_manager else 0,
        "miners_online": conn_manager.count_miners() if conn_manager else 0
    })

def run_http():
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)

def run_tcp_server(ip="0.0.0.0", port=5050):
    global blockchain, user_manager, conn_manager

    blockchain = Blockchain()
    user_manager = UserManager()
    conn_manager = ConnectionManager()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((ip, port))
    sock.listen(5)
    print(f"[Servidor TCP] Escuchando en {ip}:{port}")

    while True:
        conn, addr = sock.accept()
        handler = ClientHandler(conn, addr, blockchain, user_manager, conn_manager)
        handler.start()

if __name__ == "__main__":
    threading.Thread(target=run_http, daemon=True).start()
    run_tcp_server()
