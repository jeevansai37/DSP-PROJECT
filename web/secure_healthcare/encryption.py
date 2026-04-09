import os
from cryptography.fernet import Fernet

KEY_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(KEY_DIR, ".secret.key")


def generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)


def load_key():
    if not os.path.exists(KEY_FILE):
        raise FileNotFoundError(
            f"Encryption key file {KEY_FILE} not found. "
            "Make sure to run generate_key() first."
        )
    with open(KEY_FILE, "rb") as f:
        key = f.read()
    return key


def get_cipher():
    key = load_key()
    return Fernet(key)


def encrypt_text(plain_text: str) -> bytes:
    cipher = get_cipher()
    return cipher.encrypt(plain_text.encode("utf-8"))


def decrypt_text(token: bytes) -> str:
    cipher = get_cipher()
    return cipher.decrypt(token).decode("utf-8")