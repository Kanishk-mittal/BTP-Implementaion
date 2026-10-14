#!/usr/bin/env python3
"""
QKD-secured SSH Client Demo using upgraded paramiko.
"""
import logging
import os
import sys
import time

import paramiko
from paramiko.kex_qkd import KexQKD, QKDConfig

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def main():
    host = os.getenv("SSH_HOST", "server")
    port = int(os.getenv("SSH_PORT", "2222"))
    username = os.getenv("SSH_USERNAME", "client-sae")  # Master SAE ID = SSH username
    password = os.getenv("SSH_PASSWORD", "secret")
    target_sae_id = os.getenv("TARGET_SAE_ID", "server-sae")
    kme_url = os.getenv("KME_URL", "http://kme-a:8000")
    min_keys = int(os.getenv("QKD_MIN_AVAILABLE_KEYS", "2"))

    qkd_config = QKDConfig(
        kme_url=kme_url,
        master_sae_id=username,
        slave_sae_id=target_sae_id,
        min_available_keys=min_keys,
        verify_tls=False,
        key_size=256,
    )

    print("==================================================")
    print("      Connecting via QKD-secured Paramiko SSH     ")
    print(f" Target Host: {host}:{port}")
    print(f" Master SAE ID (Username): {username}")
    print(f" Slave SAE ID (Target):   {target_sae_id}")
    print(f" Client KME URL:          {kme_url}")
    print(f" Min Key Pool Threshold:  {min_keys}")
    print("==================================================")

    # Allow servers and KMEs a brief moment to initialize if starting fresh
    max_retries = 10
    connected = False
    for attempt in range(1, max_retries + 1):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                qkd_config=qkd_config,
                slave_sae_id=target_sae_id,
                timeout=10,
            )
            connected = True
            break
        except Exception as e:
            print(f"[RETRY {attempt}/{max_retries}] Waiting for server/KME... ({e})")
            time.sleep(2)

    if not connected:
        print("[ERROR] Failed to establish SSH connection.")
        sys.exit(1)

    t = client.get_transport()
    kex_name = getattr(t, "kex_algo", None) or (getattr(t.kex_engine, "name", None) if t and t.kex_engine else "unknown")
    print(f"\n[SUCCESS] Successfully connected!")
    print(f"[SECURITY] Key Exchange Algorithm Negotiated: {kex_name}")

    if kex_name == "qkd-etsi014-sha256":
        print("[STATUS] Connection is Quantum Key Distribution (QKD) SECURED! 🛡️")
    else:
        print("[STATUS] Connection fell back to classical key exchange.")

    # Execute a test command
    test_cmd = "uname -a && echo 'QKD SSH Session Verification OK'"
    stdin, stdout, stderr = client.exec_command(test_cmd)
    output = stdout.read().decode("utf-8")
    err_out = stderr.read().decode("utf-8")
    print("\n--- Command Output ---")
    print(output)
    if err_out:
        print("--- Stderr ---")
        print(err_out)

    client.close()
    print("[INFO] SSH connection closed cleanly.")

if __name__ == "__main__":
    main()
