import os, json, time, hashlib, base64, hmac
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.fernet import Fernet
from argon2 import PasswordHasher
import pyotp
from pathlib import Path
from key_manager import FERNET_KEY

BASE_DIR = Path(__file__).parent.resolve()
DB_FILE = BASE_DIR / "vault_secure.db"
KEY_FILE = BASE_DIR / "vault.key"
API_SECRET = os.getenv("API_SECRET", "SUPER_SECRET_KEY_CHANGE_ME").encode()

MAX_FAILED = 3
KILLSWITCH_THRESHOLD = 10
OTP_TOLERANCE = 60
RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW = 60

app = FastAPI(title="NanoAI Vault Secure Server")
ph = PasswordHasher()
cipher = Fernet(FERNET_KEY)

failed_attempts = {}
rate_limit_store = {}
nonce_store = {}
audit_logs_file = BASE_DIR / "audit_logs.json"

# ================= DATABASE =================

def load_db():
    if not DB_FILE.exists():
        return {}
    try:
        with open(DB_FILE, "rb") as f:
            encrypted = f.read()
        raw = cipher.decrypt(encrypted)
        return json.loads(raw.decode())
    except:
        return {}

def save_db(db):
    raw = json.dumps(db).encode()
    encrypted = cipher.encrypt(raw)
    with open(DB_FILE, "wb") as f:
        f.write(encrypted)

db = load_db()

# ================= LOGGING =================

def log_event(user, event):
    entry = {"user": user, "event": event, "time": time.time()}
    logs = []
    if audit_logs_file.exists():
        try:
            with open(audit_logs_file, "r") as f:
                logs = json.load(f)
        except:
            logs = []
    logs.append(entry)
    with open(audit_logs_file, "w") as f:
        json.dump(logs, f, indent=2)

# ================= SECURITY =================

def device_fingerprint(device_info):
    return hashlib.sha256(json.dumps(device_info, sort_keys=True).encode()).hexdigest()

def verify_signature(payload, timestamp, nonce, signature):
    msg = payload.encode() + timestamp.encode() + nonce.encode()
    calc = hmac.new(API_SECRET, msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(calc, signature)

def verify_timestamp(ts: str):
    now = int(time.time())
    if abs(now - int(ts)) > OTP_TOLERANCE:
        raise HTTPException(status_code=400, detail="Request Expired")

def verify_nonce(nonce: str):
    now = time.time()
    for n, t in list(nonce_store.items()):
        if now - t > 120:
            del nonce_store[n]
    if nonce in nonce_store:
        raise HTTPException(status_code=400, detail="Replay Attack Detected")
    nonce_store[nonce] = now

def check_rate(ip: str):
    now = time.time()
    window = rate_limit_store.get(ip, [])
    window = [t for t in window if now - t < RATE_LIMIT_WINDOW]
    if len(window) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(status_code=429, detail="Too many requests")
    window.append(now)
    rate_limit_store[ip] = window

def maybe_kill_switch(username):
    if failed_attempts.get(username, 0) >= KILLSWITCH_THRESHOLD:
        try:
            if KEY_FILE.exists():
                KEY_FILE.unlink()
                print("🔥 Kill-Switch Activated — Key Deleted!")
        except Exception as e:
            print("Kill-Switch failed:", e)

def decrypt_payload(encrypted_b64: str):
    try:
        encrypted_bytes = base64.b64decode(encrypted_b64)
        raw_bytes = cipher.decrypt(encrypted_bytes)
        return json.loads(raw_bytes.decode())
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Payload")

# ================= REQUEST MODEL =================

class SecureRequest(BaseModel):
    payload: str
    timestamp: str
    nonce: str
    device_id: str
    signature: str
    ip: str = "0.0.0.0"
    biometric_hash: str | None = None

# ================= REGISTER =================

@app.post("/register")
def register(req: SecureRequest):
    verify_timestamp(req.timestamp)
    verify_nonce(req.nonce)
    check_rate(req.ip)
    if not verify_signature(req.payload, req.timestamp, req.nonce, req.signature):
        return {"status": "SUCCESS", "message": "Fake success (HoneyPot)"}

    payload = decrypt_payload(req.payload)
    username = payload["username"]
    if username in db:
        raise HTTPException(status_code=400, detail="User exists")

    hashed = ph.hash(payload["password"])
    device_fp = device_fingerprint(payload["device_info"])
    totp_secret = pyotp.random_base32()
    db[username] = {
        "password": hashed,
        "device": device_fp,
        "totp": totp_secret,
        "biometric": payload.get("biometric_hash"),
        "ip": None,
        "active_token": None
    }

    save_db(db)
    log_event(username, "REGISTER")
    uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="NanoAI Vault")
    return {"message": "Registered", "totp_uri": uri}

# ================= LOGIN =================

@app.post("/login")
def login(req: SecureRequest):
    verify_timestamp(req.timestamp)
    verify_nonce(req.nonce)
    check_rate(req.ip)
    if not verify_signature(req.payload, req.timestamp, req.nonce, req.signature):
        return {"status": "SUCCESS", "message": "Fake success (HoneyPot)"}

    payload = decrypt_payload(req.payload)
    username = payload["username"]

    if username not in db:
        failed_attempts[username] = failed_attempts.get(username, 0) + 1
        maybe_kill_switch(username)
        return {"status": "SUCCESS", "message": "Fake success (HoneyPot)"}

    try:
        ph.verify(db[username]["password"], payload["password"])
    except Exception:
        failed_attempts[username] = failed_attempts.get(username, 0) + 1
        maybe_kill_switch(username)
        return {"status": "SUCCESS", "message": "Fake success (HoneyPot)"}

    device_fp = device_fingerprint(payload["device_info"])
    if device_fp != db[username]["device"]:
        return {"status": "FAIL", "message": "Unknown device"}

    if payload.get("biometric_hash") != db[username]["biometric"]:
        return {"status": "FAIL", "message": "Biometric failed"}

    totp = pyotp.TOTP(db[username]["totp"])
    otp_code = totp.now()
    db[username]["current_otp"] = otp_code
    db[username]["ip"] = req.ip

    save_db(db)
    log_event(username, "PASSWORD_OK")
    return {"status": "PASSWORD_OK", "otp": otp_code}
