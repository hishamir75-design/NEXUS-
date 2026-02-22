from cryptography.fernet import Fernet
import os

KEY_FILE = "../vault.key"

def load_key():
    if not os.path.exists(KEY_FILE):
        raise RuntimeError("vault.key not found!")
    with open(KEY_FILE, "rb") as f:
        return f.read()

FERNET_KEY = load_key()
