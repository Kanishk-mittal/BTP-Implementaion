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
import collections
import json
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

KME_ID = os.getenv("KME_ID", "KME")

# ── In-memory log ring buffer for dashboard ──────────────────────────────────
_log_lock = threading.Lock()
_log_buffer = collections.deque(maxlen=200)
_stats = {
    "keys_delivered": 0,
    "keys_consumed": 0,
    "challenges_issued": 0,
    "challenges_verified": 0,
    "total_requests": 0,
    "start_time": time.time(),
}

def _log(msg: str, level: str = "INFO"):
    entry = {
        "ts": time.strftime("%H:%M:%S"),
        "level": level,
        "msg": msg,
    }
    with _log_lock:
        _log_buffer.append(entry)
    print(f"[{KME_ID}] {entry['ts']} [{level}] {msg}", flush=True)


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
                new_len = r.rpush(POOL_LIST, kid)
                _log(f"+ Generated key {kid[:8]}... | Pool: {new_len}/{MAX_POOL} (interval: {interval:.1f}s)", "REFILL")
        except Exception as e:
            _log(f"Error in refill loop: {e}", "ERROR")
        time.sleep(interval)

# Only start background refill on one of the KMEs or if master KME
if os.getenv("START_REFILL", "true").lower() in ("1", "true", "yes"):
    t = threading.Thread(target=_refill_loop, daemon=True)
    t.start()

# ── Detailed API Request / Response Logging ──────────────────────────────

@app.before_request
def log_request_info():
    if request.path.startswith(("/favicon.ico", "/dashboard")):
        return
    with _log_lock:
        _stats["total_requests"] += 1
    payload = request.get_json(silent=True)
    body_str = ""
    if payload:
        clean_p = dict(payload)
        if "sae_cert" in clean_p:
            clean_p["sae_cert"] = f"<X.509 PEM base64 {len(clean_p['sae_cert'])} chars>"
        if "challenge_response" in clean_p:
            clean_p["challenge_response"] = f"<Signature {clean_p['challenge_response'][:20]}...>"
        body_str = f" | Body: {json.dumps(clean_p)}"
    elif request.args:
        body_str = f" | Args: {dict(request.args)}"
    _log(f">>> {request.method} {request.path} (from {request.remote_addr}){body_str}", "REQ")

@app.after_request
def log_response_info(response):
    if request.path.startswith(("/favicon.ico", "/dashboard")):
        return response
    try:
        data = response.get_json()
        if data:
            data_preview = dict(data)
            if "keys" in data_preview:
                keys_preview = []
                for k in data_preview["keys"]:
                    key_val = k.get("key", "")
                    keys_preview.append({"key_ID": k.get("key_ID"), "key": f"{key_val[:8]}... (256-bit)"})
                data_preview["keys"] = keys_preview
            _log(f"<<< {response.status} {request.path} | {json.dumps(data_preview)}", "RESP")
        else:
            _log(f"<<< {response.status} {request.path}", "RESP")
    except Exception:
        _log(f"<<< {response.status} {request.path}", "RESP")
    return response

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
    rem = r.llen(POOL_LIST)
    with _log_lock:
        _stats["keys_delivered"] += 1
    _log(f"Pop/Deliver key {kid[:8]}... to {slave_sae_id} | Pool remaining: {rem}/{MAX_POOL}", "KEY")
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
    with _log_lock:
        _stats["challenges_issued"] += 1
    _log(f"Challenge issued: {challenge_id[:8]}... (30s TTL)", "CHALLENGE")
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
            _log(f"Certificate verification failed for {master_sae_id}: {e}", "ERROR")
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
            _log(f"Signature verification failed for {master_sae_id}: {e}", "ERROR")
            return jsonify({"message": f"Challenge signature verification failed: {e}"}), 401

        with _log_lock:
            _stats["challenges_verified"] += 1

    # Deliver key material (one-time use via GETDEL)
    results = []
    for item in body.get("key_IDs", []):
        kid = item.get("key_ID", "")
        key_b64 = r.getdel(KEY_HASH_PFX + kid)  # atomically retrieve + delete
        if not key_b64:
            return jsonify({"message": f"one or more keys specified are not found on KME"}), 400
        with _log_lock:
            _stats["keys_consumed"] += 1
        _log(f"Challenge verified for {master_sae_id}. Key {kid[:8]}... consumed & deleted (one-time-use).", "KEY")
        results.append({"key_ID": kid, "key": key_b64})

    return jsonify({"keys": results})

# ── Dashboard API endpoints (for the web dashboard) ────────────────────────

@app.route("/dashboard/stats", methods=["GET"])
def dashboard_stats():
    """Live stats for the web dashboard."""
    try:
        pool_count = r.llen(POOL_LIST)
    except Exception:
        pool_count = 0
    uptime_secs = int(time.time() - _stats["start_time"])
    with _log_lock:
        s = dict(_stats)
    return jsonify({
        "kme_id": KME_ID,
        "peer_kme_id": os.getenv("PEER_KME_ID", ""),
        "master_sae_id": os.getenv("MASTER_SAE_ID", ""),
        "pool_size": pool_count,
        "max_pool": MAX_POOL,
        "pool_pct": round(pool_count / MAX_POOL * 100) if MAX_POOL else 0,
        "key_size_bits": KEY_SIZE_BITS,
        "refill_rate": REFILL_RATE,
        "enable_challenge": ENABLE_CHALLENGE,
        "keys_delivered": s["keys_delivered"],
        "keys_consumed": s["keys_consumed"],
        "challenges_issued": s["challenges_issued"],
        "challenges_verified": s["challenges_verified"],
        "total_requests": s["total_requests"],
        "uptime_secs": uptime_secs,
    })

@app.route("/dashboard/logs", methods=["GET"])
def dashboard_logs():
    """Recent log entries for the web dashboard."""
    limit = int(request.args.get("limit", 100))
    with _log_lock:
        entries = list(_log_buffer)[-limit:]
    return jsonify(entries)

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False)
