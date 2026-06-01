# server/main.py

import json
import socket
import ssl
import threading
import time
import uuid
from pathlib import Path

from server.auth import register_user
from server.connection_manager import ConnectionManager
from server.file_manager import init_storage
from server.protocol_handler import ProtocolHandler
from server.utils.logger import get_server_logger
from shared.constants import (
    DEFAULT_HOST, DEFAULT_PORT,
    TIMEOUT_SECONDS, MAX_MESSAGE_SIZE,
    STATE_CLOSED,
)

logger = get_server_logger()

# ---------- Konfiguracja TLS ----------

SSL_CERTFILE = Path("server/certs/server.crt")
SSL_KEYFILE  = Path("server/certs/server.key")

WATCHDOG_INTERVAL = 10   # sekundy między sprawdzeniami timeoutów


# ------------------------------------------------------------------ #
#  Warstwa sieciowa — jeden klient                                    #
# ------------------------------------------------------------------ #

def _recv_message(sock: ssl.SSLSocket) -> str | None:
    """
    Odbiera jedną wiadomość JSON zakończoną znakiem nowej linii.
    Zwraca None przy zerwaniu połączenia lub przekroczeniu limitu rozmiaru.
    """
    buf = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except (OSError, ssl.SSLError) as e:
            logger.debug(f"Błąd odbioru danych: {e}")
            return None

        if not chunk:
            return None

        buf += chunk
        if len(buf) > MAX_MESSAGE_SIZE:
            logger.warning("Wiadomość przekracza MAX_MESSAGE_SIZE — odrzucam")
            return None

        if b"\n" in buf:
            line, _ = buf.split(b"\n", 1)
            return line.decode("utf-8", errors="replace")


def _send_message(sock: ssl.SSLSocket, msg: dict) -> bool:
    """
    Serializuje słownik do JSON i wysyła z \\n jako separatorem.
    Zwraca False przy błędzie wysyłki.
    """
    try:
        raw = json.dumps(msg, separators=(",", ":")) + "\n"
        sock.sendall(raw.encode("utf-8"))
        return True
    except (OSError, ssl.SSLError) as e:
        logger.debug(f"Błąd wysyłki: {e}")
        return False


# ------------------------------------------------------------------ #
#  Obsługa jednego klienta (wątek)                                    #
# ------------------------------------------------------------------ #

def _handle_client(
    sock: ssl.SSLSocket,
    address: tuple,
    manager: ConnectionManager,
) -> None:
    conn_id = str(uuid.uuid4())[:12]
    conn    = manager.register(conn_id, address)

    def send_fn(msg: dict) -> None:
        _send_message(sock, msg)

    handler = ProtocolHandler(conn, send_fn)

    try:
        while True:
            # Sprawdź timeout
            if conn.is_timed_out(TIMEOUT_SECONDS):
                logger.warning(
                    f"[{conn_id}] Timeout — zamykam połączenie"
                )
                break

            # Odbierz wiadomość
            raw = _recv_message(sock)
            if raw is None:
                logger.info(f"[{conn_id}] Klient rozłączył się")
                break

            # Przekaż do protocol handlera
            handler.handle(raw)

            # Jeśli stan CLOSED — klient wysłał BYE lub wystąpił błąd krytyczny
            if conn.get_state() == STATE_CLOSED:
                logger.info(f"[{conn_id}] Stan CLOSED — zamykam połączenie")
                break

    except Exception as e:
        logger.error(f"[{conn_id}] Nieoczekiwany błąd: {e}", exc_info=True)

    finally:
        # Sprzątanie
        if conn.session_id:
            from server.auth import invalidate_session
            invalidate_session(conn.session_id)

        if conn.active_file:
            from server.file_manager import abort_upload
            abort_upload(conn.active_file)

        manager.unregister(conn_id)

        try:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        except OSError:
            pass


# ------------------------------------------------------------------ #
#  Watchdog — sprawdza timed-out połączenia                           #
# ------------------------------------------------------------------ #

def _watchdog(manager: ConnectionManager, stop_event: threading.Event) -> None:
    """
    Osobny wątek sprawdzający co WATCHDOG_INTERVAL sekund
    czy któreś połączenie nie przekroczyło timeoutu.
    Loguje ostrzeżenia — faktyczne zamknięcie obsługuje wątek klienta.
    """
    logger.info("Watchdog uruchomiony")
    while not stop_event.is_set():
        time.sleep(WATCHDOG_INTERVAL)
        timed_out = manager.timed_out_connections(TIMEOUT_SECONDS)
        for conn in timed_out:
            logger.warning(
                f"[Watchdog] Timed-out: {conn.conn_id} | "
                f"user={conn.username} | state={conn.get_state()}"
            )
        active = manager.count()
        if active:
            logger.debug(f"[Watchdog] Aktywne połączenia: {active}")
    logger.info("Watchdog zatrzymany")


# ------------------------------------------------------------------ #
#  TLS context                                                        #
# ------------------------------------------------------------------ #

def _build_ssl_context() -> ssl.SSLContext:
    if not SSL_CERTFILE.exists() or not SSL_KEYFILE.exists():
        raise FileNotFoundError(
            f"Certyfikaty TLS nie znalezione:\n"
            f"  cert: {SSL_CERTFILE}\n"
            f"  key:  {SSL_KEYFILE}\n"
            f"Wygeneruj je komendą:\n"
            f"  openssl req -x509 -newkey rsa:4096 -keyout {SSL_KEYFILE} "
            f"-out {SSL_CERTFILE} -days 365 -nodes"
        )

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=SSL_CERTFILE, keyfile=SSL_KEYFILE)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


# ------------------------------------------------------------------ #
#  Główna pętla serwera                                               #
# ------------------------------------------------------------------ #

def run_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    # Inicjalizacja storage
    init_storage()

    # SSL
    ssl_ctx = _build_ssl_context()

    # ConnectionManager
    manager    = ConnectionManager()
    stop_event = threading.Event()

    # Watchdog
    watchdog_thread = threading.Thread(
        target=_watchdog,
        args=(manager, stop_event),
        daemon=True,
        name="watchdog",
    )
    watchdog_thread.start()

    # Gniazdo nasłuchujące
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_sock:
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind((host, port))
        raw_sock.listen(16)

        with ssl_ctx.wrap_socket(raw_sock, server_side=True) as server_sock:
            logger.info(
                f"Serwer nasłuchuje na {host}:{port} (TLS)"
            )
            logger.info(
                f"Aktywni użytkownicy: {manager.count()} | "
                f"MAX_FILE={50}MB | TIMEOUT={TIMEOUT_SECONDS}s"
            )

            try:
                while True:
                    try:
                        client_sock, address = server_sock.accept()
                    except ssl.SSLError as e:
                        logger.warning(f"Błąd TLS handshake: {e}")
                        continue
                    except OSError:
                        break

                    t = threading.Thread(
                        target=_handle_client,
                        args=(client_sock, address, manager),
                        daemon=True,
                        name=f"client-{address[0]}:{address[1]}",
                    )
                    t.start()

            except KeyboardInterrupt:
                logger.info("Zatrzymywanie serwera (Ctrl+C)…")

            finally:
                stop_event.set()
                logger.info(
                    f"Serwer zatrzymany | "
                    f"obsłużono połączeń aktywnych: {manager.count()}"
                )


# ------------------------------------------------------------------ #
#  Punkt wejścia                                                      #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SecureShare Server")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", default=DEFAULT_PORT, type=int)
    parser.add_argument(
        "--add-user", nargs=2, metavar=("USERNAME", "PASSWORD"),
        help="Dodaj użytkownika i zakończ",
    )
    args = parser.parse_args()

    if args.add_user:
        username, password = args.add_user
        ok = register_user(username, password)
        print(f"{'✓' if ok else '✗'} Użytkownik '{username}' "
              f"{'dodany' if ok else 'już istnieje'}.")
    else:
        run_server(args.host, args.port)