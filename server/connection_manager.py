# server/connection_manager.py

import threading
import time
from typing import Optional

from server.utils.logger import get_server_logger
from shared.constants import (
    STATE_DISCONNECTED, STATE_CONNECTED, STATE_AUTHENTICATED,
    STATE_TRANSFERRING, STATE_CLOSED,
)

logger = get_server_logger()


# ---------- Reprezentacja pojedynczego połączenia ----------

class ClientConnection:
    """Przechowuje stan jednego podłączonego klienta."""

    def __init__(self, conn_id: str, address: tuple):
        self.conn_id:     str          = conn_id
        self.address:     tuple        = address          # (ip, port)
        self.state:       str          = STATE_DISCONNECTED
        self.session_id:  Optional[str] = None
        self.username:    Optional[str] = None
        self.hmac_secret: Optional[bytes] = None

        # Ochrona przed replay attacks
        self.seen_msg_ids:   set[str] = set()
        self.last_msg_time:  float    = time.time()

        # Transfer w toku
        self.active_file:    Optional[str] = None         # nazwa pliku podczas transferu

        # Statystyki
        self.connected_at:   float = time.time()
        self.messages_recv:  int   = 0
        self.messages_sent:  int   = 0

        self._lock = threading.Lock()

    # --- Bezpieczna zmiana stanu ---

    def set_state(self, new_state: str) -> None:
        with self._lock:
            old = self.state
            self.state = new_state
            logger.debug(
                f"[{self.conn_id}] Stan: {old} → {new_state}"
            )

    def get_state(self) -> str:
        with self._lock:
            return self.state

    # --- Sesja ---

    def attach_session(
        self,
        session_id: str,
        username: str,
        hmac_secret: bytes,
    ) -> None:
        with self._lock:
            self.session_id  = session_id
            self.username    = username
            self.hmac_secret = hmac_secret

    def clear_session(self) -> None:
        with self._lock:
            self.session_id  = None
            self.username    = None
            self.hmac_secret = None

    # --- Replay protection ---

    def is_duplicate(self, msg_id: str) -> bool:
        with self._lock:
            if msg_id in self.seen_msg_ids:
                return True
            self.seen_msg_ids.add(msg_id)
            # Nie trzymamy więcej niż 1000 ID — zapobiegamy memory leak
            if len(self.seen_msg_ids) > 1000:
                self.seen_msg_ids.pop()
            return False

    def update_last_msg_time(self) -> None:
        with self._lock:
            self.last_msg_time = time.time()

    def is_timed_out(self, timeout: float) -> bool:
        with self._lock:
            return (time.time() - self.last_msg_time) > timeout

    # --- Statystyki ---

    def record_recv(self) -> None:
        with self._lock:
            self.messages_recv += 1

    def record_sent(self) -> None:
        with self._lock:
            self.messages_sent += 1

    def uptime(self) -> float:
        return time.time() - self.connected_at

    def summary(self) -> dict:
        with self._lock:
            return {
                "conn_id":       self.conn_id,
                "address":       f"{self.address[0]}:{self.address[1]}",
                "state":         self.state,
                "username":      self.username,
                "uptime_s":      round(self.uptime(), 1),
                "messages_recv": self.messages_recv,
                "messages_sent": self.messages_sent,
                "active_file":   self.active_file,
            }

    def __repr__(self) -> str:
        return (
            f"<ClientConnection id={self.conn_id} "
            f"addr={self.address[0]}:{self.address[1]} "
            f"state={self.state} user={self.username}>"
        )


# ---------- Menedżer wszystkich połączeń ----------

class ConnectionManager:
    """
    Rejestr wszystkich aktywnych połączeń.
    Thread-safe — może być używany z wielu wątków jednocześnie.
    """

    def __init__(self):
        self._connections: dict[str, ClientConnection] = {}
        self._lock = threading.Lock()

    # --- Rejestracja ---

    def register(self, conn_id: str, address: tuple) -> ClientConnection:
        conn = ClientConnection(conn_id, address)
        with self._lock:
            self._connections[conn_id] = conn
        logger.info(f"Nowe połączenie | id={conn_id} | addr={address[0]}:{address[1]}")
        return conn

    def unregister(self, conn_id: str) -> None:
        with self._lock:
            conn = self._connections.pop(conn_id, None)
        if conn:
            logger.info(
                f"Rozłączono | id={conn_id} | user={conn.username} "
                f"| uptime={conn.uptime():.1f}s"
            )

    # --- Wyszukiwanie ---

    def get(self, conn_id: str) -> Optional[ClientConnection]:
        with self._lock:
            return self._connections.get(conn_id)

    def get_by_session(self, session_id: str) -> Optional[ClientConnection]:
        with self._lock:
            for conn in self._connections.values():
                if conn.session_id == session_id:
                    return conn
        return None

    def get_by_username(self, username: str) -> Optional[ClientConnection]:
        with self._lock:
            for conn in self._connections.values():
                if conn.username == username:
                    return conn
        return None

    # --- Przegląd ---

    def count(self) -> int:
        with self._lock:
            return len(self._connections)

    def all_summaries(self) -> list[dict]:
        with self._lock:
            return [c.summary() for c in self._connections.values()]

    def timed_out_connections(self, timeout: float) -> list[ClientConnection]:
        """Zwraca listę połączeń, które przekroczyły timeout."""
        with self._lock:
            conns = list(self._connections.values())
        return [c for c in conns if c.is_timed_out(timeout)]

    def __repr__(self) -> str:
        return f"<ConnectionManager active={self.count()}>"