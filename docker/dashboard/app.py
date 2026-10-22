#!/usr/bin/env python3
"""
ETSI GS QKD 014 Demonstration Dashboard Backend
Aggregates live metrics and logs from KME-A, KME-B, and SSH Server nodes.
"""
import os
import socket
import time
from flask import Flask, jsonify, render_template, request
import requests

app = Flask(__name__)

KME_A_URL = os.getenv("KME_A_URL", "http://kme-a:8000")
KME_B_URL = os.getenv("KME_B_URL", "http://kme-b:8000")
SERVER_HOST = os.getenv("SERVER_HOST", "server")
SERVER_PORT = int(os.getenv("SERVER_PORT", "2222"))
SERVER2_HOST = os.getenv("SERVER2_HOST", "server2")
SERVER2_PORT = int(os.getenv("SERVER2_PORT", "2222"))

def check_tcp_port(host, port, timeout=0.8):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/overview")
def api_overview():
    # Fetch KME-A stats
    kme_a_data = None
    try:
        r = requests.get(f"{KME_A_URL}/dashboard/stats", timeout=1.0)
        if r.status_code == 200:
            kme_a_data = r.json()
    except Exception as e:
        kme_a_data = {"error": str(e), "online": False}

    # Fetch KME-B stats
    kme_b_data = None
    try:
        r = requests.get(f"{KME_B_URL}/dashboard/stats", timeout=1.0)
        if r.status_code == 200:
            kme_b_data = r.json()
    except Exception as e:
        kme_b_data = {"error": str(e), "online": False}

    # Ping SSH server nodes
    server_online = check_tcp_port(SERVER_HOST, SERVER_PORT)
    server2_online = check_tcp_port(SERVER2_HOST, SERVER2_PORT)

    return jsonify({
        "timestamp": time.strftime("%H:%M:%S"),
        "kme_a": kme_a_data or {"online": False},
        "kme_b": kme_b_data or {"online": False},
        "nodes": {
            "server": {
                "name": "SSH Server 1 (QKD-Enabled)",
                "host": f"{SERVER_HOST}:{SERVER_PORT}",
                "online": server_online,
                "qkd_supported": True,
                "kme_attached": "KME-B",
                "sae_id": "server-sae",
                "default_kex": "qkd-etsi014-sha256"
            },
            "server2": {
                "name": "SSH Server 2 (No-KME Fallback Node)",
                "host": f"{SERVER2_HOST}:{SERVER2_PORT}",
                "online": server2_online,
                "qkd_supported": False,
                "kme_attached": "None (No KME)",
                "sae_id": "None",
                "default_kex": "mlkem768x25519-sha256"
            }
        }
    })

@app.route("/api/logs/kme-a")
def logs_kme_a():
    limit = request.args.get("limit", 100)
    try:
        r = requests.get(f"{KME_A_URL}/dashboard/logs?limit={limit}", timeout=1.0)
        return jsonify(r.json() if r.status_code == 200 else [])
    except Exception:
        return jsonify([])

@app.route("/api/logs/kme-b")
def logs_kme_b():
    limit = request.args.get("limit", 100)
    try:
        r = requests.get(f"{KME_B_URL}/dashboard/logs?limit={limit}", timeout=1.0)
        return jsonify(r.json() if r.status_code == 200 else [])
    except Exception:
        return jsonify([])

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
