# server/utils/crypto.py

import hmac
import hashlib
import secrets
import base64
import json
from pathlib import Path


# ---------- HMAC ----------

def compute_hmac(msg: dict, secret: bytes) -> str:
    """Liczy HMAC-SHA256 dla wiadomości (pole hmac traktowane jako puste)."""
    msg_copy = {**msg, "hmac": ""}
    raw = json.dumps(msg_copy, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(secret, raw, hashlib.sha256).hexdigest()


def verify_hmac(msg: dict, secret: bytes) -> bool:
    """Weryfikuje HMAC wiadomości. Używa compare_digest przeciw timing attacks."""
    expected = compute_hmac(msg, secret)
    received = msg.get("hmac", "")
    return hmac.compare_digest(expected, received)


# ---------- Hasła ----------

def hash_password(password: str) -> str:
    """Hashuje hasło używając SHA-256 + losowy salt. Zwraca 'salt:hash' jako string."""
    salt = secrets.token_hex(32)
    pw_hash = _hash_with_salt(password, salt)
    return f"{salt}:{pw_hash}"


def verify_password(password: str, stored: str) -> bool:
    """Weryfikuje hasło względem zapisanego 'salt:hash'."""
    try:
        salt, expected_hash = stored.split(":", 1)
    except ValueError:
        return False
    actual_hash = _hash_with_salt(password, salt)
    return hmac.compare_digest(expected_hash, actual_hash)


def _hash_with_salt(password: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()


# ---------- Session token ----------

def generate_session_id() -> str:
    """Generuje kryptograficznie bezpieczny session ID."""
    return secrets.token_urlsafe(32)


# ---------- Checksum pliku ----------

def compute_file_checksum(data: bytes) -> str:
    """Liczy SHA-256 checksum dla danych pliku."""
    return hashlib.sha256(data).hexdigest()


def verify_file_checksum(data: bytes, expected: str) -> bool:
    """Weryfikuje SHA-256 checksum pliku."""
    actual = compute_file_checksum(data)
    return hmac.compare_digest(actual, expected)


# ---------- Klucz HMAC sesji ----------

def generate_hmac_secret() -> bytes:
    """Generuje losowy 32-bajtowy klucz HMAC dla sesji."""
    return secrets.token_bytes(32)


def hmac_secret_to_b64(secret: bytes) -> str:
    return base64.b64encode(secret).decode()


def hmac_secret_from_b64(s: str) -> bytes:
    return base64.b64decode(s.encode())