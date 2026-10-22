#!/usr/bin/env python3
"""
QKD-secured SSH Server using upgraded paramiko.
"""
import logging
import os
import socket
import subprocess
import sys
import threading

import paramiko
from paramiko.kex_qkd import QKDConfig

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(name)s] [%(levelname)s] %(message)s",
    stream=sys.stdout
)
logging.getLogger("paramiko").setLevel(logging.DEBUG)

class SuppressBannerErrorFilter(logging.Filter):
    def filter(self, record):
        msg = record.getMessage()
        if "Error reading SSH protocol banner" in msg or "EOFError" in msg:
            return False
        return True

logging.getLogger("paramiko.transport").addFilter(SuppressBannerErrorFilter())

auth_map = {}
for pair in os.getenv("AUTHORIZED_USERS", "client-sae:secret").split(","):
    if ":" in pair:
        u, p = pair.split(":", 1)
        auth_map[u.strip()] = p.strip()

class QKDServerInterface(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        expected_pw = auth_map.get(username)
        if expected_pw and expected_pw == password:
            print(f"[AUTH] User '{username}' authenticated successfully via password.")
            return paramiko.AUTH_SUCCESSFUL
        print(f"[AUTH] Password authentication failed for user '{username}'.")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        cmd_str = command.decode("utf-8") if isinstance(command, bytes) else str(command)
        print(f"[EXEC] Executing command: {cmd_str}")
        try:
            res = subprocess.run(cmd_str, shell=True, capture_output=True)
            channel.sendall(res.stdout)
            if res.stderr:
                channel.sendall_stderr(res.stderr)
            channel.send_exit_status(res.returncode)
            channel.shutdown_write()
        except Exception as e:
            channel.sendall_stderr(str(e).encode("utf-8"))
            channel.send_exit_status(1)
            channel.shutdown_write()
        return True

def handle_client(client_sock, host_key, qkd_config):
    try:
        t = paramiko.Transport(client_sock, qkd_config=qkd_config)
        t.add_server_key(host_key)
        server = QKDServerInterface()
        t.start_server(server=server)
        chan = t.accept(30)
        if chan is not None:
            # Keep channel alive until closed by client
            while not chan.closed:
                threading.Event().wait(0.5)
    except Exception as e:
        if "Error reading SSH protocol banner" not in str(e):
            print(f"[CONN] Handshake/transport error: {e}")
    finally:
        try:
            client_sock.close()
        except Exception:
            pass

def main():
    host_key_path = os.getenv("HOST_KEY_PATH", "/certs/host_rsa_key")
    if not os.path.exists(host_key_path):
        print(f"[ERROR] Host key not found at {host_key_path}")
        sys.exit(1)

    host_key = paramiko.RSAKey(filename=host_key_path)

    enable_qkd = os.getenv("ENABLE_QKD", "true").lower() in ("1", "true", "yes")
    kme_url = os.getenv("KME_URL", "http://kme-b:8000").strip()

    if enable_qkd and kme_url:
        qkd_config = QKDConfig(
            kme_url=kme_url,
            slave_sae_id=os.getenv("SERVER_SAE_ID", "server-sae"),
            server_cert_file=os.getenv("SERVER_CERT_FILE", "/certs/server_ca.crt"),
            server_key_file=os.getenv("SERVER_KEY_FILE", "/certs/server_ca.key"),
            verify_tls=False,
            key_size=256,
        )
        print(f"[INFO] QKD Key Exchange ENABLED (KME: {kme_url}, SAE: {qkd_config.slave_sae_id})")
    else:
        qkd_config = None
        print("[INFO] Running in CLASSICAL mode (No KME attached). QKD disabled.")

    port = int(os.getenv("SSH_PORT", "2222"))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(10)
    server_mode_str = "QKD-Secured" if qkd_config else "Classical (No-KME)"
    print(f"[INFO] {server_mode_str} SSH Server listening on port {port}...")

    while True:
        client, addr = sock.accept()
        print(f"[INFO] Incoming connection from {addr}")
        t = threading.Thread(target=handle_client, args=(client, host_key, qkd_config), daemon=True)
        t.start()

if __name__ == "__main__":
    main()
