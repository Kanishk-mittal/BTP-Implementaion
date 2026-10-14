#!/bin/sh
set -e
CERTS=/certs
mkdir -p "$CERTS"

echo "[CA] Generating CA key and self-signed certificate..."
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
  -keyout "$CERTS/ca.key" -out "$CERTS/ca.crt" \
  -subj "/CN=QKD-Demo-CA/O=QKD-Demo"

echo "[CA] Generating server CA-issued key and certificate (for KME challenge-response)..."
openssl req -newkey rsa:2048 -nodes \
  -keyout "$CERTS/server_ca.key" -out "$CERTS/server_ca.csr" \
  -subj "/CN=server-sae/O=QKD-Demo"
openssl x509 -req -in "$CERTS/server_ca.csr" \
  -CA "$CERTS/ca.crt" -CAkey "$CERTS/ca.key" -CAcreateserial \
  -out "$CERTS/server_ca.crt" -days 365

echo "[CA] Generating SSH RSA host key..."
python3 - <<'PYEOF'
import paramiko
k = paramiko.RSAKey.generate(2048)
k.write_private_key_file("/certs/host_rsa_key")
print("[CA] SSH host key written to /certs/host_rsa_key")
PYEOF

chmod 644 "$CERTS"/*.crt "$CERTS"/*.csr 2>/dev/null || true
chmod 600 "$CERTS"/*.key "$CERTS"/host_rsa_key 2>/dev/null || true
echo "[CA] All certificates generated successfully:"
ls -la "$CERTS/"
