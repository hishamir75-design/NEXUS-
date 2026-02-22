import requests, hashlib, json, platform, secrets, socket, time, hmac, base64
from client_key import FERNET_KEY
from cryptography.fernet import Fernet

SERVER_URL = 'https://127.0.0.1:8000'
API_SECRET = b"SUPER_SECRET_KEY_CHANGE_ME"
session = requests.Session()
cipher = Fernet(FERNET_KEY)

def get_device_info():
    return {
        'os': platform.system(),
        'os_version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor()
    }

def get_device_id():
    raw = platform.node() + platform.machine()
    return hashlib.sha256(raw.encode()).hexdigest()

def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '127.0.0.1'

def hash_biometric(raw_biometric: str):
    return hashlib.sha256(raw_biometric.encode()).hexdigest()

def encrypt_payload(payload: dict):
    raw = json.dumps(payload).encode()
    encrypted = cipher.encrypt(raw)
    return base64.b64encode(encrypted).decode()

def sign_payload(payload_b64: str, timestamp: str, nonce: str):
    msg = payload_b64.encode() + timestamp.encode() + nonce.encode()
    return hmac.new(API_SECRET, msg, hashlib.sha256).hexdigest()

def secure_post(endpoint: str, payload: dict):
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    payload_b64 = encrypt_payload(payload)
    signature = sign_payload(payload_b64, timestamp, nonce)

    response = session.post(
        f"{SERVER_URL}{endpoint}",
        json={
            "payload": payload_b64,
            "timestamp": timestamp,
            "nonce": nonce,
            "device_id": get_device_id(),
            "signature": signature,
            "ip": get_ip()
        },
        timeout=10,
        verify=False
    )
    return response.json()

def register(username, password, raw_biometric):
    payload = {
        "username": username,
        "password": password,
        "device_info": get_device_info(),
        "biometric_hash": hash_biometric(raw_biometric)
    }
    return secure_post("/register", payload)

def login(username, password, raw_biometric):
    payload = {
        "username": username,
        "password": password,
        "device_info": get_device_info(),
        "ip": get_ip(),
        "biometric_hash": hash_biometric(raw_biometric)
    }
    return secure_post("/login", payload)
