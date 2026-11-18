#!/usr/bin/env python3
"""
QKD-secured SSH Client API Daemon.
Exposes REST endpoints to trigger on-demand SSH connections with QKD or fallback.
"""
import logging
import os
import sys
import time

from flask import Flask, jsonify, request
import paramiko
from paramiko.kex_qkd import QKDConfig

is_verbose = os.getenv("VERBOSE", "1").lower() in ("1", "true", "yes")
log_level = logging.DEBUG if is_verbose else logging.INFO
logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(name)s] [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
logging.getLogger("paramiko").setLevel(log_level)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

app = Flask(__name__)

DEFAULT_HOST = os.getenv("SSH_HOST", "server")
DEFAULT_PORT = int(os.getenv("SSH_PORT", "2222"))
DEFAULT_USERNAME = os.getenv("SSH_USERNAME", "client-sae")
DEFAULT_PASSWORD = os.getenv("SSH_PASSWORD", "secret")
DEFAULT_TARGET_SAE_ID = os.getenv("TARGET_SAE_ID", "server-sae")
DEFAULT_KME_URL = os.getenv("KME_URL", "http://kme-a:8000")
DEFAULT_MIN_KEYS = int(os.getenv("QKD_MIN_AVAILABLE_KEYS", "2"))


def execute_ssh(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    command: str = "whoami",
    username: str = DEFAULT_USERNAME,
    password: str = DEFAULT_PASSWORD,
    target_sae_id: str = DEFAULT_TARGET_SAE_ID,
    kme_url: str = DEFAULT_KME_URL,
    min_keys: int = DEFAULT_MIN_KEYS,
    timeout: float = 10.0,
):
    """
    Establishes an SSH connection with QKDConfig, executes the command,
    and returns session security metadata and command output.
    """
    start_time = time.time()
    qkd_config = QKDConfig(
        kme_url=kme_url,
        master_sae_id=username,
        slave_sae_id=target_sae_id,
        min_available_keys=min_keys,
        verify_tls=False,
        key_size=256,
    )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            qkd_config=qkd_config,
            slave_sae_id=target_sae_id,
            timeout=timeout,
        )

        transport = client.get_transport()
        kex_name = getattr(transport, "kex_algo", None) or (
            getattr(transport.kex_engine, "name", None)
            if transport and transport.kex_engine
            else "unknown"
        )

        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        stdout_str = stdout.read().decode("utf-8", errors="replace")
        stderr_str = stderr.read().decode("utf-8", errors="replace")
        exit_status = stdout.channel.recv_exit_status()

        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        is_qkd = kex_name == "qkd-etsi014-sha256"

        return {
            "success": True,
            "target": f"{host}:{port}",
            "command": command,
            "kex_algo": kex_name,
            "is_qkd": is_qkd,
            "exit_status": exit_status,
            "stdout": stdout_str,
            "stderr": stderr_str,
            "elapsed_ms": elapsed_ms,
            "timestamp": time.strftime("%H:%M:%S"),
        }
    except Exception as exc:
        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        return {
            "success": false if "false" in locals() else False,
            "target": f"{host}:{port}",
            "command": command,
            "error": str(exc),
            "elapsed_ms": elapsed_ms,
            "timestamp": time.strftime("%H:%M:%S"),
        }
    finally:
        try:
            client.close()
        except Exception:
            pass


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "qkd-ssh-client-api"})


@app.route("/api/exec", methods=["GET", "POST"])
def api_exec():
    payload = {}
    if request.is_json:
        payload = request.get_json(silent=True) or {}
    elif request.form:
        payload = dict(request.form)

    # Allow query parameter overrides as well
    host = request.args.get("target") or request.args.get("host") or payload.get("target") or payload.get("host") or DEFAULT_HOST
    port = int(request.args.get("port") or payload.get("port") or DEFAULT_PORT)
    command = request.args.get("command") or payload.get("command") or "whoami"
    username = request.args.get("username") or payload.get("username") or DEFAULT_USERNAME
    password = request.args.get("password") or payload.get("password") or DEFAULT_PASSWORD
    target_sae = request.args.get("target_sae_id") or payload.get("target_sae_id") or DEFAULT_TARGET_SAE_ID
    kme_url = request.args.get("kme_url") or payload.get("kme_url") or DEFAULT_KME_URL
    min_keys = int(request.args.get("min_keys") or payload.get("min_keys") or DEFAULT_MIN_KEYS)

    result = execute_ssh(
        host=host,
        port=port,
        command=command,
        username=username,
        password=password,
        target_sae_id=target_sae,
        kme_url=kme_url,
        min_keys=min_keys,
    )

    status_code = 200 if result.get("success") else 500
    return jsonify(result), status_code


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    print(f"[CLIENT-API] Starting QKD SSH Client API daemon on port {port}...", flush=True)
    app.run(host="0.0.0.0", port=port, debug=False)
