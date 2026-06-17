# server/protocol_handler.py

import json
from typing import Optional

from server.auth import (
    authenticate,
    get_hmac_secret,
    get_username,
    invalidate_session,
    is_authenticated,
)
from server.file_manager import (
    upload_start,
    upload_chunk,
    upload_end,
    abort_upload,
    download_prepare,
    get_file_checksum,
    list_files,
)
from server.connection_manager import ClientConnection
from server.utils.crypto import verify_hmac, hmac_secret_to_b64
from server.utils.logger import get_protocol_logger
from shared.constants import (
    ERR_INVALID_FORMAT, ERR_AUTH_FAILED, ERR_UNAUTHORIZED,
    ERR_DUPLICATE_MESSAGE, ERR_FILE_TOO_LARGE, ERR_TIMEOUT,
    MSG_HELLO, MSG_AUTH, MSG_AUTH_OK, MSG_AUTH_FAIL,
    MSG_UPLOAD_START, MSG_UPLOAD_CHUNK, MSG_UPLOAD_END,
    MSG_DOWNLOAD_REQ, MSG_DOWNLOAD_CHUNK,
    MSG_LIST_REQUEST, MSG_LIST_RESPONSE,
    MSG_ACK, MSG_ERROR, MSG_PING, MSG_PONG, MSG_BYE,
    STATE_DISCONNECTED, STATE_CONNECTED, STATE_AUTHENTICATED,
    STATE_TRANSFERRING, STATE_CLOSED,
    MAX_FILE_SIZE_BYTES,
)
from shared.message_schema import build_message, build_ack, build_error
from shared.protocol_definitions import validate_payload, get_next_state

logger = get_protocol_logger()


class ProtocolHandler:
    """
    Obsługuje logikę protokołu dla jednego połączenia klienta.
    Każde połączenie ma własną instancję ProtocolHandler.
    """

    def __init__(self, conn: ClientConnection, send_fn):
        """
        conn    — obiekt ClientConnection z connection_manager
        send_fn — callable(msg: dict) wysyłający wiadomość do klienta
        """
        self.conn    = conn
        self._send   = send_fn

    # ------------------------------------------------------------------ #
    #  Punkt wejścia — każda odebrana wiadomość trafia tutaj              #
    # ------------------------------------------------------------------ #

    def handle(self, raw: str) -> None:
        """Parsuje i obsługuje jedną wiadomość od klienta."""

        # 1. Parsowanie JSON
        msg = self._parse(raw)
        if msg is None:
            return

        msg_type   = msg.get("type", "")
        session_id = msg.get("session_id", "")
        msg_id     = msg.get("msg_id", "")
        payload    = msg.get("payload", {})

        logger.debug(
            f"[{self.conn.conn_id}] ← {msg_type} | msg_id={msg_id[:8]}…"
        )

        # 2. Weryfikacja HMAC (po AUTH — kiedy mamy już secret)
        if self.conn.hmac_secret:
            if not verify_hmac(msg, self.conn.hmac_secret):
                logger.warning(
                    f"[{self.conn.conn_id}] Nieprawidłowy HMAC | type={msg_type}"
                )
                self._send_error(ERR_INVALID_FORMAT, "Nieprawidłowy HMAC")
                return

        # 3. Ochrona przed duplikatami
        if msg_id and self.conn.is_duplicate(msg_id):
            logger.warning(
                f"[{self.conn.conn_id}] Duplikat wiadomości | msg_id={msg_id[:8]}…"
            )
            self._send_error(ERR_DUPLICATE_MESSAGE, "Duplikat wiadomości")
            return

        # 4. Walidacja payloadu
        ok, err = validate_payload(msg_type, payload)
        if not ok:
            self._send_error(ERR_INVALID_FORMAT, err)
            return

        # 5. Aktualizacja timera
        self.conn.update_last_msg_time()
        self.conn.record_recv()

        # 6. Routing do handlera
        handler = self._get_handler(msg_type)
        if handler is None:
            self._send_error(ERR_INVALID_FORMAT, f"Nieznany typ wiadomości: {msg_type}")
            return

        handler(msg_id, session_id, payload)

    # ------------------------------------------------------------------ #
    #  Parsowanie                                                          #
    # ------------------------------------------------------------------ #

    def _parse(self, raw: str) -> Optional[dict]:
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning(f"[{self.conn.conn_id}] Błąd parsowania JSON")
            self._send_error(ERR_INVALID_FORMAT, "Nieprawidłowy format JSON")
            return None

        for field in ("type", "session_id", "msg_id", "timestamp", "payload", "hmac"):
            if field not in msg:
                self._send_error(
                    ERR_INVALID_FORMAT, f"Brakujące pole wiadomości: '{field}'"
                )
                return None

        return msg

    # ------------------------------------------------------------------ #
    #  Routing                                                             #
    # ------------------------------------------------------------------ #

    def _get_handler(self, msg_type: str):
        return {
            MSG_HELLO:        self._handle_hello,
            MSG_AUTH:         self._handle_auth,
            MSG_UPLOAD_START: self._handle_upload_start,
            MSG_UPLOAD_CHUNK: self._handle_upload_chunk,
            MSG_UPLOAD_END:   self._handle_upload_end,
            MSG_DOWNLOAD_REQ: self._handle_download_request,
            MSG_LIST_REQUEST: self._handle_list_request,
            MSG_PING:         self._handle_ping,
            MSG_BYE:          self._handle_bye,
            MSG_ACK:          self._handle_ack,
            MSG_ERROR:        self._handle_error,
        }.get(msg_type)

    # ------------------------------------------------------------------ #
    #  Handlery wiadomości                                                 #
    # ------------------------------------------------------------------ #

    def _handle_hello(self, msg_id: str, session_id: str, payload: dict) -> None:
        if self.conn.get_state() != STATE_DISCONNECTED:
            self._send_error(ERR_INVALID_FORMAT, "Nieoczekiwane HELLO")
            return

        client_version = payload.get("client_version", "?")
        logger.info(
            f"[{self.conn.conn_id}] HELLO | client_version={client_version}"
        )
        self.conn.set_state(STATE_CONNECTED)
        self._send_ack(msg_id)

    def _handle_auth(self, msg_id: str, session_id: str, payload: dict) -> None:
        if self.conn.get_state() != STATE_CONNECTED:
            self._send_error(ERR_UNAUTHORIZED, "AUTH niedozwolony w tym stanie")
            return

        username = payload["username"]
        password = payload["password"]

        result = authenticate(username, password)
        if result is None:
            logger.warning(
                f"[{self.conn.conn_id}] AUTH nieudany | user='{username}'"
            )
            self.conn.set_state(STATE_CLOSED)
            self._send(build_message(
                MSG_AUTH_FAIL, "",
                {"reason": "Nieprawidłowy login lub hasło"},
            ))
            return

        new_session_id, hmac_secret = result
        self.conn.attach_session(new_session_id, username, hmac_secret)
        self.conn.set_state(STATE_AUTHENTICATED)

        logger.info(
            f"[{self.conn.conn_id}] AUTH OK | user='{username}' "
            f"| session={new_session_id[:12]}…"
        )
        self._send(build_message(
            MSG_AUTH_OK, new_session_id,
            {"session_id": new_session_id, "hmac_secret": hmac_secret_to_b64(hmac_secret)},
            hmac_secret,
        ))

    def _handle_upload_start(self, msg_id: str, session_id: str, payload: dict) -> None:
        if not self._require_state(STATE_AUTHENTICATED, msg_id):
            return

        filename = payload["filename"]
        filesize = payload["filesize"]
        checksum = payload["checksum"]

        if filesize > MAX_FILE_SIZE_BYTES:
            self._send_error(
                ERR_FILE_TOO_LARGE,
                f"Plik zbyt duży: {filesize}B (max {MAX_FILE_SIZE_BYTES}B)",
            )
            return

        ok, err = upload_start(filename, filesize, checksum, self.conn.username)
        if not ok:
            self._send_error(ERR_INVALID_FORMAT, err)
            return

        self.conn.active_file = filename
        self.conn.set_state(STATE_TRANSFERRING)
        self._send_ack(msg_id)

    def _handle_upload_chunk(self, msg_id: str, session_id: str, payload: dict) -> None:
        if not self._require_state(STATE_TRANSFERRING, msg_id):
            return

        filename    = self.conn.active_file
        chunk_index = payload["chunk_index"]
        data_b64    = payload["data"]

        ok, err = upload_chunk(filename, chunk_index, data_b64)
        if not ok:
            self._send_error(ERR_INVALID_FORMAT, err)
            abort_upload(filename)
            self.conn.active_file = None
            self.conn.set_state(STATE_AUTHENTICATED)
            return

        self._send_ack(msg_id)

    def _handle_upload_end(self, msg_id: str, session_id: str, payload: dict) -> None:
        if not self._require_state(STATE_TRANSFERRING, msg_id):
            return

        filename     = self.conn.active_file
        total_chunks = payload["total_chunks"]

        ok, err = upload_end(filename, total_chunks)
        if not ok:
            self._send_error(ERR_INVALID_FORMAT, err)
            abort_upload(filename)
        else:
            checksum = get_file_checksum(filename)
            self._send(build_message(
                MSG_ACK, self.conn.session_id,
                {"ref_msg_id": msg_id, "filename": filename, "checksum": checksum},
                self.conn.hmac_secret,
            ))

        self.conn.active_file = None
        self.conn.set_state(STATE_AUTHENTICATED)

    def _handle_download_request(self, msg_id: str, session_id: str, payload: dict) -> None:
        if not self._require_state(STATE_AUTHENTICATED, msg_id):
            return

        filename = payload["filename"]
        self.conn.set_state(STATE_TRANSFERRING)

        chunks, err = download_prepare(filename)
        if chunks is None:
            self._send_error(ERR_INVALID_FORMAT, err)
            self.conn.set_state(STATE_AUTHENTICATED)
            return

        checksum    = get_file_checksum(filename)
        total       = len(chunks)

        logger.info(
            f"[{self.conn.conn_id}] Download start | "
            f"file='{filename}' | chunks={total}"
        )

        for i, chunk_b64 in enumerate(chunks):
            self._send(build_message(
                MSG_DOWNLOAD_CHUNK, self.conn.session_id,
                {
                    "chunk_index":  i,
                    "total_chunks": total,
                    "data":         chunk_b64,
                    "checksum":     checksum if i == total - 1 else "",
                },
                self.conn.hmac_secret,
            ))
            self.conn.record_sent()

        self.conn.set_state(STATE_AUTHENTICATED)
        logger.info(
            f"[{self.conn.conn_id}] Download zakończony | file='{filename}'"
        )

    def _handle_list_request(self, msg_id: str, session_id: str, payload: dict) -> None:
        if not self._require_state(STATE_AUTHENTICATED, msg_id):
            return

        files = list_files()
        logger.info(
            f"[{self.conn.conn_id}] LIST | user='{self.conn.username}' "
            f"| plików={len(files)}"
        )
        self._send(build_message(
            MSG_LIST_RESPONSE, self.conn.session_id,
            {"ref_msg_id": msg_id, "files": files},
            self.conn.hmac_secret,
        ))
        self.conn.record_sent()

    def _handle_ping(self, msg_id: str, session_id: str, payload: dict) -> None:
        self._send(build_message(
            MSG_PONG, self.conn.session_id or "",
            {},
            self.conn.hmac_secret,
        ))

    def _handle_bye(self, msg_id: str, session_id: str, payload: dict) -> None:
        logger.info(
            f"[{self.conn.conn_id}] BYE | user='{self.conn.username}'"
        )
        self._send_ack(msg_id)
        if self.conn.session_id:
            invalidate_session(self.conn.session_id)
        self.conn.clear_session()
        self.conn.set_state(STATE_CLOSED)

    def _handle_ack(self, msg_id: str, session_id: str, payload: dict) -> None:
        ref_msg_id = payload.get("ref_msg_id", "")
        logger.debug(
            f"[{self.conn.conn_id}] Odebrano ACK dla msg_id={ref_msg_id[:8]}…"
        )

    def _handle_error(self, msg_id: str, session_id: str, payload: dict) -> None:
        code = payload.get("code", 0)
        desc = payload.get("description", "")
        logger.warning(
            f"[{self.conn.conn_id}] Klient zgłosił błąd {code}: {desc}"
        )

    # ------------------------------------------------------------------ #
    #  Helpery                                                             #
    # ------------------------------------------------------------------ #

    def _require_state(self, expected: str, msg_id: str) -> bool:
        """Sprawdza czy połączenie jest w wymaganym stanie."""
        current = self.conn.get_state()
        if current != expected:
            self._send_error(
                ERR_UNAUTHORIZED,
                f"Niedozwolona operacja w stanie {current} (wymagany: {expected})",
            )
            return False
        return True

    def _send_ack(self, ref_msg_id: str) -> None:
        msg = build_ack(
            self.conn.session_id or "",
            ref_msg_id,
            self.conn.hmac_secret,
        )
        self._send(msg)
        self.conn.record_sent()

    def _send_error(self, code: int, description: str) -> None:
        msg = build_error(
            self.conn.session_id or "",
            code,
            description,
            self.conn.hmac_secret,
        )
        self._send(msg)
        self.conn.record_sent()
        logger.warning(
            f"[{self.conn.conn_id}] ERROR {code} → {description}"
        )