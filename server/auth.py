# server/auth.py

import json
import time
from pathlib import Path
from typing import Optional

from server.utils.crypto import (
    hash_password,
    verify_password,
    generate_session_id,
    generate_hmac_secret,
    hmac_secret_to_b64,
    hmac_secret_from_b64,
)
from server.utils.logger import get_auth_logger

logger = get_auth_logger()

USERS_FILE = Path("server/users.json")

# Struktura pliku users.json:
# {
#   "alice": { "password_hash": "salt:hash" },
#   "bob":   { "password_hash": "salt:hash" }
# }


# ---------- Zarządzanie użytkownikami ----------

def _load_users() -> dict:
    if not USERS_FILE.exists():
        logger.warning("Plik users.json nie istnieje, tworzę pusty.")
        _save_users({})
        return {}
    try:
        return json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        logger.error(f"Błąd parsowania users.json: {e}")
        return {}


def _save_users(users: dict) -> None:
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    USERS_FILE.write_text(
        json.dumps(users, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def register_user(username: str, password: str) -> bool:
    """Rejestruje nowego użytkownika. Zwraca False jeśli już istnieje."""
    users = _load_users()
    if username in users:
        logger.warning(f"Próba rejestracji istniejącego użytkownika: '{username}'")
        return False
    users[username] = {"password_hash": hash_password(password)}
    _save_users(users)
    logger.info(f"Zarejestrowano użytkownika: '{username}'")
    return True


def user_exists(username: str) -> bool:
    return username in _load_users()


# ---------- Sesje ----------

# Słownik aktywnych sesji:
# { session_id: { "username": str, "hmac_secret": str(b64), "created_at": int } }
_active_sessions: dict[str, dict] = {}


def authenticate(username: str, password: str) -> Optional[tuple[str, bytes]]:
    """
    Weryfikuje dane logowania.
    Zwraca (session_id, hmac_secret) przy sukcesie, None przy niepowodzeniu.
    """
    users = _load_users()

    if username not in users:
        logger.warning(f"Nieznany użytkownik: '{username}'")
        return None

    stored_hash = users[username].get("password_hash", "")
    if not verify_password(password, stored_hash):
        logger.warning(f"Błędne hasło dla użytkownika: '{username}'")
        return None

    session_id  = generate_session_id()
    hmac_secret = generate_hmac_secret()

    _active_sessions[session_id] = {
        "username":    username,
        "hmac_secret": hmac_secret_to_b64(hmac_secret),
        "created_at":  int(time.time()),
    }

    logger.info(f"Zalogowano użytkownika '{username}' | session={session_id[:12]}…")
    return session_id, hmac_secret


def get_session(session_id: str) -> Optional[dict]:
    """Zwraca dane sesji lub None jeśli sesja nie istnieje."""
    return _active_sessions.get(session_id)


def get_hmac_secret(session_id: str) -> Optional[bytes]:
    """Zwraca klucz HMAC dla sesji lub None."""
    session = _active_sessions.get(session_id)
    if not session:
        return None
    return hmac_secret_from_b64(session["hmac_secret"])


def get_username(session_id: str) -> Optional[str]:
    """Zwraca nazwę użytkownika powiązaną z sesją."""
    session = _active_sessions.get(session_id)
    return session["username"] if session else None


def invalidate_session(session_id: str) -> None:
    """Usuwa sesję (wylogowanie / BYE / błąd)."""
    session = _active_sessions.pop(session_id, None)
    if session:
        logger.info(
            f"Sesja zakończona | user='{session['username']}' "
            f"| session={session_id[:12]}…"
        )


def is_authenticated(session_id: str) -> bool:
    return session_id in _active_sessions


# ---------- Narzędzie CLI do dodawania użytkowników ----------

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Użycie: python -m server.auth <username> <password>")
        sys.exit(1)

    username, password = sys.argv[1], sys.argv[2]
    ok = register_user(username, password)
    if ok:
        print(f"✓ Użytkownik '{username}' dodany.")
    else:
        print(f"✗ Użytkownik '{username}' już istnieje.")