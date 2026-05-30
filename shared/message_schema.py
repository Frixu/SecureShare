# shared/message_schema.py

import time
import uuid
import hmac
import hashlib
import json
from shared.constants import MSG_ACK, MSG_ERROR


def generate_msg_id() -> str:
    return str(uuid.uuid4())


def generate_session_id() -> str:
    return str(uuid.uuid4())


def get_timestamp() -> int:
    return int(time.time())


def build_message(
    msg_type: str,
    session_id: str,
    payload: dict,
    hmac_secret: bytes | None = None,
    msg_id: str | None = None,
) -> dict:
    """Buduje słownik wiadomości zgodny z protokołem."""
    msg = {
        "type":       msg_type,
        "session_id": session_id,
        "msg_id":     msg_id or generate_msg_id(),
        "timestamp":  get_timestamp(),
        "payload":    payload,
        "hmac":       "",
    }
    if hmac_secret:
        msg["hmac"] = compute_hmac(msg, hmac_secret)
    return msg


def compute_hmac(msg: dict, secret: bytes) -> str:
    """Liczy HMAC-SHA256 dla wiadomości (pole hmac traktowane jako puste)."""
    msg_copy = {**msg, "hmac": ""}
    raw = json.dumps(msg_copy, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(secret, raw, hashlib.sha256).hexdigest()


def verify_hmac(msg: dict, secret: bytes) -> bool:
    expected = compute_hmac(msg, secret)
    return hmac.compare_digest(expected, msg.get("hmac", ""))


def build_ack(session_id: str, ref_msg_id: str, hmac_secret: bytes | None = None) -> dict:
    return build_message(MSG_ACK, session_id, {"ref_msg_id": ref_msg_id}, hmac_secret)


def build_error(session_id: str, code: int, description: str,
                hmac_secret: bytes | None = None) -> dict:
    return build_message(
        MSG_ERROR, session_id,
        {"code": code, "description": description},
        hmac_secret,
    )