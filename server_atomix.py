from flask import Flask, request, jsonify
import threading
import time
import hashlib
from decimal import Decimal
from math import floor

app = Flask(__name__)

# Simulación simple blockchain y usuarios
blockchain = []
users = {}
connections = {}

MINING_REWARD = Decimal("100.0")

class Block:
    def __init__(self, index, timestamp, data, previous_hash, nonce):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.compute_hash()
    
    def compute_hash(self):
        import json
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

def init_blockchain():
    if len(blockchain) == 0:
        genesis_block = Block(0, time.time(), {"genesis": True}, "0", 0)
        blockchain.append(genesis_block)

def get_last_block():
    return blockchain[-1]

def add_block(block):
    last_block = get_last_block()
    if last_block.hash != block.previous_hash:
        return False
    if block.hash != block.compute_hash():
        return False
    blockchain.append(block)
    return True

def register_user(username, pin):
    if username in users:
        return False, "Usuario ya existe"
    users[username] = {
        "pin": pin,
        "balance": Decimal("0"),
        "mining_power": Decimal("1"),
        "mining_time": 0
    }
    return True, "Usuario registrado"

def authenticate(username, pin):
    user = users.get(username)
    if not user:
        return False
    return user["pin"] == pin

def update_user(username, user_data):
    users[username] = user_data
    slots = max(1, floor(user_data["mining_power"]))
    return slots, user_data["mining_power"], user_data["balance"]

@app.route('/', methods=['POST'])
def main_api():
    try:
        msg = request.get_json()
        if not msg:
            return jsonify({"error": "No JSON received"}), 400
        
        mtype = msg.get("type")
        
        if mtype == "request_chain":
            chain_data = []
            for b in blockchain:
                chain_data.append({
                    "index": b.index,
                    "timestamp": b.timestamp,
                    "data": b.data,
                    "previous_hash": b.previous_hash,
                    "nonce": b.nonce,
                    "hash": b.hash
                })
            return jsonify({"type": "chain_response", "chain": chain_data})

        elif mtype == "new_block":
            block_data = msg.get("block")
            block = Block(
                block_data['index'],
                block_data['timestamp'],
                block_data['data'],
                block_data['previous_hash'],
                block_data['nonce']
            )
            # Override hash (as client computed)
            block.hash = block_data['hash']

            username = block.data.get("usuario")
            reward = Decimal(str(block.data.get("recompensa", "0")))

            if add_block(block):
                user_data = users.get(username)
                if user_data:
                    user_data["balance"] += reward
                    user_data["mining_time"] += 1
                    slots, mining_power, balance = update_user(username, user_data)
                    # add connection simulation (skip)
                return jsonify({"type": "block_accepted", "index": block.index})
            else:
                return jsonify({"type": "block_rejected", "index": block.index})

        elif mtype == "register":
            username = msg.get("username")
            pin = msg.get("pin")
            ok, message = register_user(username, pin)
            return jsonify({"type": "register_response", "ok": ok, "message": message})

        elif mtype == "login":
            username = msg.get("username")
            pin = msg.get("pin")
            if authenticate(username, pin):
                user_data = users.get(username)
                slots = max(1, floor(user_data["mining_power"]))
                return jsonify({
                    "type": "login_response",
                    "ok": True,
                    "balance": float(user_data["balance"]),
                    "mining_power": float(user_data["mining_power"]),
                    "slots": slots,
                    "miners_online": len(connections)
                })
            else:
                return jsonify({"type": "login_response", "ok": False, "message": "Credenciales incorrectas"})

        elif mtype == "burn":
            username = msg.get("username")
            amount = Decimal(str(msg.get("amount", "0")))
            user_data = users.get(username)
            if not user_data:
                return jsonify({"type": "burn_response", "ok": False, "message": "Usuario no encontrado"})
            if user_data["balance"] < amount:
                return jsonify({"type": "burn_response", "ok": False, "message": "Saldo insuficiente"})
            user_data["balance"] -= amount
            user_data["mining_power"] += amount * Decimal("0.1")  # Ejemplo incremento poder
            update_user(username, user_data)
            return jsonify({"type": "burn_response", "ok": True, "message": "Monedas quemadas, poder minero aumentado"})

        else:
            return jsonify({"error": "Accion desconocida"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    init_blockchain()
    app.run(host='0.0.0.0', port=5050)
