# client/client.py

import json
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

from client.transfer import DownloadBuffer, prepare_upload_chunks
from client.utils.logger import get_client_logger, get_protocol_logger
from shared.constants import (
    DEFAULT_HOST, DEFAULT_PORT,
    TIMEOUT_SECONDS, MAX_RETRIES,
    STATE_DISCONNECTED, STATE_CONNECTED, STATE_AUTHENTICATED,
    STATE_TRANSFERRING, STATE_CLOSED,
    MSG_HELLO, MSG_AUTH, MSG_AUTH_OK, MSG_AUTH_FAIL,
    MSG_UPLOAD_START, MSG_UPLOAD_CHUNK, MSG_UPLOAD_END,
    MSG_DOWNLOAD_REQ, MSG_DOWNLOAD_CHUNK,
    MSG_ACK, MSG_ERROR, MSG_PING, MSG_PONG, MSG_BYE,
)
from shared.message_schema import build_message, build_ack, verify_hmac
from shared.protocol_definitions import validate_payload, get_next_state

logger = get_client_logger()
protocol_logger = get_protocol_logger()


class SecureShareClient:
    """
    Main client class handling network connection, protocol states,
    retransmissions, keep-alive PING/PONG, and file transfers.
    """

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self.state = STATE_DISCONNECTED
        
        self.session_id: Optional[str] = None
        self.hmac_secret: Optional[bytes] = None
        self.username: Optional[str] = None

        self._raw_sock: Optional[socket.socket] = None
        self._sock: Optional[ssl.SSLSocket] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._ping_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Thread synchronization for requests & responses
        self._lock = threading.Lock()
        self._pending_requests: Dict[str, threading.Event] = {}
        self._received_responses: Dict[str, dict] = {}
        self._last_sent_msg_type: Optional[str] = None
        self._last_sent_msg_id: Optional[str] = None

        # Replay attack protection
        self.seen_msg_ids: Set[str] = set()

        # Download buffer
        self._active_download: Optional[DownloadBuffer] = None
        self._download_completed_event = threading.Event()
        self._download_error: Optional[str] = None

    # --- Connection and State Management ---

    def set_state(self, new_state: str) -> None:
        with self._lock:
            old = self.state
            self.state = new_state
            logger.debug(f"Stan klienta: {old} → {new_state}")

    def get_state(self) -> str:
        with self._lock:
            return self.state

    def connect(self) -> bool:
        """Establishes connection to server and does HELLO handshake."""
        if self.get_state() != STATE_DISCONNECTED:
            logger.warning("Klient jest już połączony.")
            return True

        self._stop_event.clear()
        
        try:
            # TLS Client Setup
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # Self-signed certs fallback

            self._raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._raw_sock.settimeout(10.0)
            
            logger.info(f"Nawiązywanie połączenia TLS z {self.host}:{self.port}...")
            self._sock = ctx.wrap_socket(self._raw_sock, server_hostname=self.host)
            self._sock.connect((self.host, self.port))
            self._sock.do_handshake()
            self._sock.settimeout(None)  # Blocking in reader thread

            # Start reader thread
            self._reader_thread = threading.Thread(
                target=self._reader_loop, 
                daemon=True, 
                name="client-reader"
            )
            self._reader_thread.start()
            
            logger.info("Połączenie sieciowe nawiązane. Rozpoczynanie uścisku dłoni (HELLO)...")
            
            # Send HELLO with retry
            resp = self._send_with_retry(MSG_HELLO, {"client_version": "1.0"})
            if resp and resp.get("type") == MSG_ACK:
                self.set_state(STATE_CONNECTED)
                logger.info("Uścisk dłoni (HELLO) zakończony pomyślnie.")
                return True
            else:
                logger.error("Brak poprawnej odpowiedzi ACK na HELLO.")
                self.disconnect()
                return False

        except Exception as e:
            logger.error(f"Nie udało się połączyć z serwerem: {e}")
            self.disconnect()
            return False

    def disconnect(self) -> None:
        """Closes sockets and stops threads, setting state to CLOSED/DISCONNECTED."""
        self._stop_event.set()
        self.set_state(STATE_CLOSED)

        # Wake up any waiting request threads
        with self._lock:
            for event in self._pending_requests.values():
                event.set()
            self._download_completed_event.set()

        # Close SSL Socket
        if self._sock:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
                self._sock.close()
            except OSError:
                pass
            self._sock = None

        # Close Raw Socket
        if self._raw_sock:
            try:
                self._raw_sock.close()
            except OSError:
                pass
            self._raw_sock = None

        self.session_id = None
        self.hmac_secret = None
        self.username = None
        self.set_state(STATE_DISCONNECTED)
        logger.info("Rozłączono z serwerem.")

    # --- Communication ---

    def _send_message(self, msg: dict) -> bool:
        """Serializes message to JSON and sends it with a newline terminator."""
        if not self._sock:
            return False
        try:
            raw = json.dumps(msg, separators=(",", ":")) + "\n"
            self._sock.sendall(raw.encode("utf-8"))
            protocol_logger.debug(f"→ {msg['type']} | msg_id={msg['msg_id'][:8]}...")
            return True
        except (OSError, ssl.SSLError) as e:
            logger.error(f"Błąd wysyłania wiadomości: {e}")
            return False

    def _send_with_retry(self, msg_type: str, payload: dict) -> Optional[dict]:
        """
        Sends a message, waits for response. Retries up to 3 times on timeout.
        If no response after 3 retries, closes connection.
        """
        for retry in range(1, MAX_RETRIES + 1):
            if self._stop_event.is_set():
                return None

            # Build message
            msg = build_message(
                msg_type=msg_type,
                session_id=self.session_id or "",
                payload=payload,
                hmac_secret=self.hmac_secret
            )
            msg_id = msg["msg_id"]
            
            # Register response event
            event = threading.Event()
            with self._lock:
                self._pending_requests[msg_id] = event
                self._last_sent_msg_type = msg_type
                self._last_sent_msg_id = msg_id

            # Send
            if not self._send_message(msg):
                with self._lock:
                    self._pending_requests.pop(msg_id, None)
                return None

            # Wait for response
            if event.wait(TIMEOUT_SECONDS):
                # Response received!
                with self._lock:
                    self._pending_requests.pop(msg_id, None)
                    resp = self._received_responses.pop(msg_id, None)
                
                if resp:
                    if resp.get("type") == MSG_ERROR:
                        err_payload = resp.get("payload", {})
                        logger.error(f"Serwer zwrócił błąd {err_payload.get('code')}: {err_payload.get('description')}")
                    return resp
                return None
            else:
                logger.warning(
                    f"Brak odpowiedzi na {msg_type} (próba {retry}/{MAX_RETRIES}). "
                    f"Ponawianie za chwilę..."
                )

        logger.error("Brak odpowiedzi od serwera po maksymalnej liczbie prób. Rozłączanie.")
        self.disconnect()
        return None

    # --- Reader Loop ---

    def _reader_loop(self) -> None:
        """Runs in background to read incoming messages from the socket."""
        logger.debug("Wątek odbiorcy uruchomiony.")
        buffer = b""
        
        try:
            while not self._stop_event.is_set():
                chunk = self._sock.recv(4096)
                if not chunk:
                    logger.info("Połączenie zamknięte przez serwer.")
                    break
                
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    raw_msg = line.decode("utf-8", errors="replace").strip()
                    if raw_msg:
                        self._handle_received_message(raw_msg)
                        
        except (OSError, ssl.SSLError) as e:
            if not self._stop_event.is_set():
                logger.error(f"Błąd wątku odbiorcy: {e}")
        finally:
            if not self._stop_event.is_set():
                self.disconnect()
            logger.debug("Wątek odbiorcy zakończony.")

    def _handle_received_message(self, raw: str) -> None:
        """Parses, validates, and routes a single received JSON message."""
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("Odebrano nieprawidłowy format JSON.")
            return

        # Basic fields validation
        for field in ("type", "session_id", "msg_id", "timestamp", "payload", "hmac"):
            if field not in msg:
                logger.warning(f"Odebrana wiadomość nie zawiera pola '{field}'")
                return

        msg_type = msg["type"]
        msg_id = msg["msg_id"]
        payload = msg["payload"]
        
        protocol_logger.debug(f"← {msg_type} | msg_id={msg_id[:8]}...")

        # Verify HMAC if secret is available
        if self.hmac_secret:
            if not verify_hmac(msg, self.hmac_secret):
                logger.warning(f"Odrzucono wiadomość {msg_type} z nieprawidłowym HMAC.")
                return

        # Replay Attack Protection
        with self._lock:
            if msg_id in self.seen_msg_ids:
                logger.warning(f"Wykryto zduplikowany msg_id: {msg_id}")
                return
            self.seen_msg_ids.add(msg_id)
            if len(self.seen_msg_ids) > 1000:
                self.seen_msg_ids.pop()

        # Routing
        if msg_type == MSG_PONG:
            logger.debug("Odebrano PONG (Keep-alive).")
            return
            
        elif msg_type == MSG_DOWNLOAD_CHUNK:
            self._handle_download_chunk(msg)
            return

        # Handle request/response matching
        ref_msg_id = payload.get("ref_msg_id", "")
        
        if ref_msg_id:
            # Direct match via ref_msg_id
            with self._lock:
                if ref_msg_id in self._pending_requests:
                    self._received_responses[ref_msg_id] = msg
                    self._pending_requests[ref_msg_id].set()
                    return
        
        # State-based matching (e.g. AUTH_OK / AUTH_FAIL have no ref_msg_id)
        with self._lock:
            if msg_type in (MSG_AUTH_OK, MSG_AUTH_FAIL) and self._last_sent_msg_type == MSG_AUTH:
                last_id = self._last_sent_msg_id
                if last_id and last_id in self._pending_requests:
                    self._received_responses[last_id] = msg
                    self._pending_requests[last_id].set()
                    return

        logger.warning(f"Otrzymano nieoczekiwaną wiadomość typu {msg_type} (brak oczekującego żądania).")

    # --- Keep-Alive Thread ---

    def _keep_alive_loop(self) -> None:
        """Sends PING to server every 30 seconds when authenticated."""
        logger.debug("Wątek keep-alive uruchomiony.")
        while not self._stop_event.is_set():
            time.sleep(30)
            if self._stop_event.is_set() or self.get_state() != STATE_AUTHENTICATED:
                break
            
            logger.debug("Wysyłanie PING...")
            ping_msg = build_message(
                msg_type=MSG_PING,
                session_id=self.session_id or "",
                payload={},
                hmac_secret=self.hmac_secret
            )
            self._send_message(ping_msg)
            
        logger.debug("Wątek keep-alive zakończony.")

    # --- Public API / Use Cases ---

    def login(self, username: str, password: str) -> bool:
        """UC1: Authenticates user. Returns True if successful."""
        if self.get_state() != STATE_CONNECTED:
            logger.error("Musisz najpierw połączyć się z serwerem.")
            return False

        logger.info(f"Logowanie użytkownika '{username}'...")
        resp = self._send_with_retry(MSG_AUTH, {"username": username, "password": password})
        
        if resp is None:
            return False
            
        resp_type = resp.get("type")
        if resp_type == MSG_AUTH_OK:
            payload = resp.get("payload", {})
            self.session_id = payload.get("session_id")
            hmac_b64 = payload.get("hmac_secret", "")
            
            import base64
            try:
                self.hmac_secret = base64.b64decode(hmac_b64.encode("utf-8"))
            except Exception as e:
                logger.error(f"Błąd dekodowania klucza HMAC od serwera: {e}")
                self.disconnect()
                return False

            self.username = username
            self.set_state(STATE_AUTHENTICATED)
            logger.info(f"Zalogowano pomyślnie! ID sesji: {self.session_id[:12]}...")

            # Start keep-alive thread
            self._ping_thread = threading.Thread(
                target=self._keep_alive_loop, 
                daemon=True, 
                name="client-keep-alive"
            )
            self._ping_thread.start()
            return True
            
        elif resp_type == MSG_AUTH_FAIL:
            reason = resp.get("payload", {}).get("reason", "Nieznany powód")
            logger.error(f"Logowanie nieudane: {reason}")
            self.set_state(STATE_CLOSED)
            self.disconnect()
            return False
            
        return False

    def upload_file(self, filepath_str: str) -> bool:
        """UC2: Uploads a file to the server in 8KB chunks."""
        if self.get_state() != STATE_AUTHENTICATED:
            logger.error("Musisz być zalogowany, aby wysyłać pliki.")
            return False

        # Prepare chunks
        prep = prepare_upload_chunks(filepath_str)
        if prep is None:
            return False
        
        chunks, checksum, filesize, filename = prep
        total_chunks = len(chunks)

        self.set_state(STATE_TRANSFERRING)
        logger.info(f"Inicjowanie wysyłania pliku '{filename}' ({filesize}B)...")

        # 1. UPLOAD_START
        resp = self._send_with_retry(MSG_UPLOAD_START, {
            "filename": filename,
            "filesize": filesize,
            "checksum": checksum
        })
        
        if resp is None or resp.get("type") != MSG_ACK:
            logger.error("Inicjalizacja wysyłania odrzucona przez serwer.")
            self.set_state(STATE_AUTHENTICATED)
            return False

        # 2. UPLOAD_CHUNKs
        for idx, chunk_b64 in enumerate(chunks):
            logger.info(f"Wysyłanie fragmentu {idx + 1}/{total_chunks}...")
            resp = self._send_with_retry(MSG_UPLOAD_CHUNK, {
                "chunk_index": idx,
                "data": chunk_b64
            })
            if resp is None or resp.get("type") != MSG_ACK:
                logger.error(f"Przerwano wysyłanie pliku. Błąd na fragmencie {idx}.")
                self.set_state(STATE_AUTHENTICATED)
                return False

        # 3. UPLOAD_END
        logger.info("Finalizowanie wysyłania pliku na serwerze...")
        resp = self._send_with_retry(MSG_UPLOAD_END, {
            "filename": filename,
            "total_chunks": total_chunks
        })

        if resp is None or resp.get("type") != MSG_ACK:
            logger.error("Błąd podczas finalizacji wysyłania pliku.")
            self.set_state(STATE_AUTHENTICATED)
            return False

        # Check server ACK payload to verify checksum response if sent
        ack_payload = resp.get("payload", {})
        server_checksum = ack_payload.get("checksum")
        if server_checksum and server_checksum != checksum:
            logger.error("Suma kontrolna pliku na serwerze różni się od lokalnej!")
            self.set_state(STATE_AUTHENTICATED)
            return False

        logger.info(f"Wysyłanie pliku '{filename}' zakończone pomyślnie!")
        self.set_state(STATE_AUTHENTICATED)
        return True

    def download_file(self, filename: str, dest_path_str: str) -> bool:
        """UC3: Downloads a file from the server."""
        if self.get_state() != STATE_AUTHENTICATED:
            logger.error("Musisz być zalogowany, aby pobierać pliki.")
            return False

        # Resolve destination if it's a directory
        dest_path = Path(dest_path_str)
        if dest_path_str.endswith("/") or dest_path_str.endswith("\\") or dest_path.is_dir() or dest_path.suffix == "":
            dest_path = dest_path / filename
            dest_path_str = str(dest_path)

        self._download_completed_event.clear()
        self._download_error = None
        self._active_download = DownloadBuffer(filename)
        self.set_state(STATE_TRANSFERRING)

        logger.info(f"Wysyłanie żądania pobrania pliku '{filename}'...")
        
        # 1. Send DOWNLOAD_REQUEST
        # Note: server doesn't send ACK, it starts sending MSG_DOWNLOAD_CHUNK.
        # But we still run it through send_with_retry? 
        # Wait, if we use send_with_retry for DOWNLOAD_REQUEST, the server response will be MSG_DOWNLOAD_CHUNK.
        # So send_with_retry will wait for DOWNLOAD_CHUNK, match it state-based or direct, and unblock!
        # Let's check: will the reader set the event for MSG_DOWNLOAD_REQ on receiving MSG_DOWNLOAD_CHUNK?
        # Yes, in _handle_received_message, we handle matching. Let's make sure it handles it:
        # If msg_type == MSG_DOWNLOAD_CHUNK, we process the chunk. If it is the first chunk, we should also
        # trigger/set the event of the pending DOWNLOAD_REQUEST so that the main thread knows the request succeeded!
        
        resp = self._send_with_retry(MSG_DOWNLOAD_REQ, {"filename": filename})
        if resp is None:
            # Failed to start download
            self._active_download = None
            self.set_state(STATE_AUTHENTICATED)
            return False
            
        if resp.get("type") == MSG_ERROR:
            self._active_download = None
            self.set_state(STATE_AUTHENTICATED)
            return False

        # Now wait for the reader thread to signal that download is complete
        logger.info("Oczekiwanie na pobranie wszystkich fragmentów pliku...")
        if self._download_completed_event.wait(TIMEOUT_SECONDS * 10):  # Allow longer time for download
            if self._download_error:
                logger.error(f"Pobieranie przerwane: {self._download_error}")
                self._active_download = None
                self.set_state(STATE_AUTHENTICATED)
                return False
                
            # Complete! Reassemble and save
            ok, err = self._active_download.save_and_verify(dest_path_str)
            if not ok:
                logger.error(f"Błąd składania/weryfikacji pliku: {err}")
                self._active_download = None
                self.set_state(STATE_AUTHENTICATED)
                return False

            logger.info(f"Pobieranie pliku '{filename}' zakończone pomyślnie!")
            self._active_download = None
            self.set_state(STATE_AUTHENTICATED)
            return True
        else:
            logger.error("Przekroczono limit czasu oczekiwania na pobranie pliku.")
            self._active_download = None
            self.set_state(STATE_AUTHENTICATED)
            return False

    def _handle_download_chunk(self, msg: dict) -> None:
        """Processes a download chunk received from the server."""
        payload = msg["payload"]
        chunk_index = payload["chunk_index"]
        total_chunks = payload["total_chunks"]
        data_b64 = payload["data"]
        checksum = payload.get("checksum", "")

        # Send ACK to server immediately (as required by PDF UC3)
        # Note: the ACK should have ref_msg_id = msg['msg_id']
        ack_msg = build_ack(
            session_id=self.session_id or "",
            ref_msg_id=msg["msg_id"],
            hmac_secret=self.hmac_secret
        )
        self._send_message(ack_msg)

        if not self._active_download:
            logger.warning("Odebrano fragment pliku, ale brak aktywnej sesji pobierania.")
            return

        # Add chunk
        is_complete, err = self._active_download.add_chunk(chunk_index, total_chunks, data_b64, checksum)
        if err:
            self._download_error = err
            self._download_completed_event.set()
            return

        # If this was the first chunk, check if there is a pending DOWNLOAD_REQ event to unblock
        with self._lock:
            req_id = self._last_sent_msg_id
            if req_id and self._last_sent_msg_type == MSG_DOWNLOAD_REQ:
                if req_id in self._pending_requests:
                    self._received_responses[req_id] = msg  # Give it the first chunk as success response
                    self._pending_requests[req_id].set()

        if is_complete:
            self._download_completed_event.set()

    def logout_and_exit(self) -> None:
        """Sends BYE and disconnects."""
        if self.get_state() == STATE_AUTHENTICATED:
            logger.info("Wylogowywanie (wysyłanie BYE)...")
            self._send_with_retry(MSG_BYE, {})
        self.disconnect()
