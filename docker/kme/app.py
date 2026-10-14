"""
Dummy ETSI GS QKD 014 KME with KME-B challenge-response extension.

Environment variables:
  REDIS_HOST         Redis hostname (default: redis)
  KME_ID             This KME's identifier
  PEER_KME_ID        Peer KME's identifier
  MASTER_SAE_ID      Authorized master SAE ID
  KEY_SIZE_BITS      Key size in bits (default: 256)
  MAX_POOL_SIZE      Maximum pool depth (default: 10)
  REFILL_RATE        Keys added per second (default: 2)
  ENABLE_CHALLENGE   Enable challenge-response for dec_keys (default: false)
  CA_CERT_FILE       Path to CA cert for verifying SAE identities
"""
import base64
import os
import threading
import time
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from flask import Flask, jsonify, request
import redis as redislib

app = Flask(__name__)
r = redislib.Redis(
    host=os.getenv("REDIS_HOST", "redis"), port=6379, decode_responses=True
)

KEY_SIZE_BITS = int(os.getenv("KEY_SIZE_BITS", "256"))
MAX_POOL = int(os.getenv("MAX_POOL_SIZE", "10"))
REFILL_RATE = float(os.getenv("REFILL_RATE", "2"))
ENABLE_CHALLENGE = os.getenv("ENABLE_CHALLENGE", "false").lower() in ("1", "true", "yes")
CA_CERT_FILE = os.getenv("CA_CERT_FILE", "/certs/ca.crt")
POOL_LIST = "qkd:pool"
KEY_HASH_PFX = "qkd:key:"
CHALL_PFX = "qkd:challenge:"
CHALL_TTL_SECS = 30  # challenges expire in 30 seconds

def _refill_loop():
    interval = 1.0 / REFILL_RATE if REFILL_RATE > 0 else 0.5
    while True:
        try:
            current_len = r.llen(POOL_LIST)
            if current_len < MAX_POOL:
                kid = str(uuid.uuid4())
                key_bytes = os.urandom(KEY_SIZE_BITS // 8)
                key_b64 = base64.b64encode(key_bytes).decode("ascii")
                r.set(KEY_HASH_PFX + kid, key_b64)
                r.rpush(POOL_LIST, kid)
        except Exception as e:
            app.logger.warning(f"Error in refill loop: {e}")
        time.sleep(interval)

# Only start background refill on one of the KMEs or if master KME
if os.getenv("START_REFILL", "true").lower() in ("1", "true", "yes"):
    t = threading.Thread(target=_refill_loop, daemon=True)
    t.start()

# ── ETSI GS QKD 014 endpoints ─────────────────────────────────────────────

@app.route("/api/v1/keys/<slave_sae_id>/status", methods=["GET"])
def get_status(slave_sae_id):
    try:
        count = r.llen(POOL_LIST)
    except Exception:
        count = 0
    return jsonify({
        "source_KME_ID": os.getenv("KME_ID", "KME-A"),
        "target_KME_ID": os.getenv("PEER_KME_ID", "KME-B"),
        "master_SAE_ID": os.getenv("MASTER_SAE_ID", "client-sae"),
        "slave_SAE_ID": slave_sae_id,
        "key_size": KEY_SIZE_BITS,
        "stored_key_count": count,
        "max_key_count": MAX_POOL,
        "max_key_per_request": 1,
        "max_key_size": KEY_SIZE_BITS,
        "min_key_size": KEY_SIZE_BITS,
        "max_SAE_ID_count": 0,
    })

@app.route("/api/v1/keys/<slave_sae_id>/enc_keys", methods=["POST", "GET"])
def enc_keys(slave_sae_id):
    kid = r.lpop(POOL_LIST)  # atomic pop — key removed from pool
    if not kid:
        return jsonify({"message": "Key pool exhausted"}), 503
    key_b64 = r.get(KEY_HASH_PFX + kid)
    if not key_b64:
        return jsonify({"message": f"Key data for {kid} not found"}), 500
    # Key bytes remain in Redis until Slave KME dec_keys retrieves + deletes them
    return jsonify({"keys": [{"key_ID": kid, "key": key_b64}]})

# ── Custom challenge endpoint (Slave KME ↔ Slave SAE authentication) ───────

@app.route("/api/v1/keys/challenge", methods=["GET"])
def get_challenge():
    """
    Custom extension: Slave SAE requests a challenge nonce from KME-B.
    KME-B stores the nonce with a 30-second TTL.
    """
    challenge_id = str(uuid.uuid4())
    nonce = os.urandom(32)
    nonce_b64 = base64.b64encode(nonce).decode("ascii")
    r.set(CHALL_PFX + challenge_id, nonce_b64, ex=CHALL_TTL_SECS)
    return jsonify({"challenge": nonce_b64, "challenge_id": challenge_id})

# ── Modified dec_keys with challenge verification ─────────────────────────

@app.route("/api/v1/keys/<master_sae_id>/dec_keys", methods=["POST", "GET"])
def dec_keys(master_sae_id):
    body = request.get_json(force=True, silent=True) or {}

    # Challenge-response gate (enforced when ENABLE_CHALLENGE=true)
    if ENABLE_CHALLENGE:
        challenge_id = body.get("challenge_id")
        challenge_response = body.get("challenge_response")  # base64-encoded signature
        sae_cert_b64 = body.get("sae_cert")  # base64-encoded PEM cert

        if not challenge_id or not challenge_response or not sae_cert_b64:
            return jsonify({"message": "Challenge-response required for dec_keys"}), 401

        # a. Retrieve and delete the stored nonce (replay protection)
        nonce_b64 = r.getdel(CHALL_PFX + challenge_id)
        if not nonce_b64:
            return jsonify({"message": "Challenge not found or expired"}), 401

        # b. Verify sae_cert is signed by our CA
        try:
            with open(CA_CERT_FILE, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
            sae_cert_pem = base64.b64decode(sae_cert_b64)
            sae_cert = x509.load_pem_x509_certificate(sae_cert_pem)
            ca_cert.public_key().verify(
                sae_cert.signature,
                sae_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                sae_cert.signature_hash_algorithm,
            )
        except Exception as e:
            return jsonify({"message": f"SAE certificate verification failed: {e}"}), 401

        # c. Verify the challenge signature using the SAE's cert public key
        try:
            nonce = base64.b64decode(nonce_b64)
            sig = base64.b64decode(challenge_response)
            sae_cert.public_key().verify(
                sig,
                nonce,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except Exception as e:
            return jsonify({"message": f"Challenge signature verification failed: {e}"}), 401

    # Deliver key material (one-time use via GETDEL)
    results = []
    for item in body.get("key_IDs", []):
        kid = item.get("key_ID", "")
        key_b64 = r.getdel(KEY_HASH_PFX + kid)  # atomically retrieve + delete
        if not key_b64:
            return jsonify({"message": f"one or more keys specified are not found on KME"}), 400
        results.append({"key_ID": kid, "key": key_b64})

    return jsonify({"keys": results})

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False)
