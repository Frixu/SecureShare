# shared/protocol_definitions.py

from shared.constants import (
    MSG_HELLO, MSG_AUTH, MSG_AUTH_OK, MSG_AUTH_FAIL,
    MSG_UPLOAD_START, MSG_UPLOAD_CHUNK, MSG_UPLOAD_END,
    MSG_DOWNLOAD_REQ, MSG_DOWNLOAD_CHUNK,
    MSG_ACK, MSG_ERROR, MSG_PING, MSG_PONG, MSG_BYE,
    STATE_DISCONNECTED, STATE_CONNECTED,
    STATE_AUTHENTICATED, STATE_TRANSFERRING, STATE_CLOSED,
)

# ---------- Wymagane pola payloadu per typ wiadomości ----------

PAYLOAD_SCHEMA: dict[str, list[str]] = {
    MSG_HELLO:          ["client_version"],
    MSG_AUTH:           ["username", "password"],
    MSG_AUTH_OK:        ["session_id"],
    MSG_AUTH_FAIL:      ["reason"],
    MSG_UPLOAD_START:   ["filename", "filesize", "checksum"],
    MSG_UPLOAD_CHUNK:   ["chunk_index", "data"],
    MSG_UPLOAD_END:     ["filename", "total_chunks"],
    MSG_DOWNLOAD_REQ:   ["filename"],
    MSG_DOWNLOAD_CHUNK: ["chunk_index", "total_chunks", "data"],
    MSG_ACK:            ["ref_msg_id"],
    MSG_ERROR:          ["code", "description"],
    MSG_PING:           [],
    MSG_PONG:           [],
    MSG_BYE:            [],
}

# ---------- Dozwolone przejścia stanów ----------

# {stan_bieżący: [dozwolone typy wiadomości do wysłania/odebrania]}
ALLOWED_MESSAGES_PER_STATE: dict[str, list[str]] = {
    STATE_DISCONNECTED:  [MSG_HELLO],
    STATE_CONNECTED:     [MSG_AUTH, MSG_AUTH_OK, MSG_AUTH_FAIL, MSG_PING, MSG_PONG],
    STATE_AUTHENTICATED: [MSG_UPLOAD_START, MSG_DOWNLOAD_REQ, MSG_PING, MSG_PONG, MSG_BYE],
    STATE_TRANSFERRING:  [MSG_UPLOAD_CHUNK, MSG_UPLOAD_END,
                          MSG_DOWNLOAD_CHUNK, MSG_ACK, MSG_ERROR],
    STATE_CLOSED:        [],
}

# ---------- Przejścia stanów ----------

STATE_TRANSITIONS: dict[str, dict[str, str]] = {
    # (stan_bieżący): {typ_wiadomości -> nowy_stan}
    STATE_DISCONNECTED: {
        MSG_HELLO: STATE_CONNECTED,
    },
    STATE_CONNECTED: {
        MSG_AUTH_OK:   STATE_AUTHENTICATED,
        MSG_AUTH_FAIL: STATE_CLOSED,
    },
    STATE_AUTHENTICATED: {
        MSG_UPLOAD_START:  STATE_TRANSFERRING,
        MSG_DOWNLOAD_REQ:  STATE_TRANSFERRING,
        MSG_BYE:           STATE_CLOSED,
    },
    STATE_TRANSFERRING: {
        MSG_UPLOAD_END:    STATE_AUTHENTICATED,
        MSG_DOWNLOAD_CHUNK: STATE_AUTHENTICATED,  # po ostatnim chunku
        MSG_ERROR:         STATE_CLOSED,
    },
}


def validate_payload(msg_type: str, payload: dict) -> tuple[bool, str]:
    """Sprawdza czy payload zawiera wszystkie wymagane pola."""
    required = PAYLOAD_SCHEMA.get(msg_type)
    if required is None:
        return False, f"Nieznany typ wiadomości: {msg_type}"
    missing = [f for f in required if f not in payload]
    if missing:
        return False, f"Brakujące pola w payload: {missing}"
    return True, ""


def get_next_state(current_state: str, msg_type: str) -> str | None:
    """Zwraca nowy stan po odebraniu wiadomości, lub None jeśli przejście niedozwolone."""
    return STATE_TRANSITIONS.get(current_state, {}).get(msg_type)