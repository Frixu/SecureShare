# tests/test_protocol.py
#
# Testy logiki protokołu (server/protocol_handler.py) napędzane bezpośrednio,
# bez gniazd ani TLS — dzięki temu są deterministyczne i szybkie.
#
# Pokrywają scenariusze wymagane w briefie (sekcja 13):
#   ✔ poprawny upload (i download)
#   ❌ błędne logowanie
#   🔒 nieautoryzowany dostęp
#   🔁 duplikaty / uszkodzony HMAC / zły format
#
# Uruchomienie:  python -m unittest tests.test_protocol

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import server.auth as auth
import server.file_manager as fm
from server.connection_manager import ClientConnection
from server.protocol_handler import ProtocolHandler
from shared import constants as C
from shared.message_schema import build_message


class ProtocolTestBase(unittest.TestCase):
    """Wspólny harness: świeży użytkownik 'alice', izolowane storage i sesje."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)

        # Izolacja stanu globalnego.
        self._orig_users = auth.USERS_FILE
        self._orig_uploads = fm.UPLOAD_DIR
        auth.USERS_FILE = base / "users.json"
        fm.UPLOAD_DIR = base / "uploads"
        fm.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        auth._active_sessions.clear()
        fm._upload_buffer.clear()

        auth.register_user("alice", "haslo123")

        self.sent: list[dict] = []
        self.conn = ClientConnection("test-conn", ("127.0.0.1", 0))
        self.handler = ProtocolHandler(self.conn, self.sent.append)

        self.session_id = ""
        self.secret = None

    def tearDown(self):
        auth.USERS_FILE = self._orig_users
        fm.UPLOAD_DIR = self._orig_uploads
        auth._active_sessions.clear()
        fm._upload_buffer.clear()
        self._tmp.cleanup()

    # --- pomocnicze ---

    def feed(self, msg: dict) -> None:
        self.handler.handle(json.dumps(msg))

    def last(self) -> dict:
        return self.sent[-1]

    def do_hello(self) -> None:
        self.feed(build_message(C.MSG_HELLO, "", {"client_version": "1.0"}))

    def do_auth(self, username="alice", password="haslo123") -> dict:
        self.feed(build_message(C.MSG_AUTH, "", {
            "username": username, "password": password,
        }))
        resp = self.last()
        if resp["type"] == C.MSG_AUTH_OK:
            self.session_id = resp["payload"]["session_id"]
            self.secret = base64.b64decode(resp["payload"]["hmac_secret"])
        return resp

    def signed(self, msg_type: str, payload: dict, msg_id=None) -> dict:
        return build_message(
            msg_type, self.session_id, payload,
            hmac_secret=self.secret, msg_id=msg_id,
        )


class TestHappyPath(ProtocolTestBase):

    def test_full_upload_and_download(self):
        # HELLO → CONNECTED
        self.do_hello()
        self.assertEqual(self.last()["type"], C.MSG_ACK)
        self.assertEqual(self.conn.get_state(), C.STATE_CONNECTED)

        # AUTH → AUTHENTICATED
        self.assertEqual(self.do_auth()["type"], C.MSG_AUTH_OK)
        self.assertEqual(self.conn.get_state(), C.STATE_AUTHENTICATED)

        # UPLOAD
        data = b"To jest tresc testowego pliku PDF."
        checksum = hashlib.sha256(data).hexdigest()

        self.feed(self.signed(C.MSG_UPLOAD_START, {
            "filename": "plik.pdf", "filesize": len(data), "checksum": checksum,
        }))
        self.assertEqual(self.last()["type"], C.MSG_ACK)
        self.assertEqual(self.conn.get_state(), C.STATE_TRANSFERRING)

        self.feed(self.signed(C.MSG_UPLOAD_CHUNK, {
            "chunk_index": 0, "data": base64.b64encode(data).decode(),
        }))
        self.assertEqual(self.last()["type"], C.MSG_ACK)

        self.feed(self.signed(C.MSG_UPLOAD_END, {
            "filename": "plik.pdf", "total_chunks": 1,
        }))
        self.assertEqual(self.last()["type"], C.MSG_ACK)
        self.assertEqual(self.conn.get_state(), C.STATE_AUTHENTICATED)

        # Plik faktycznie zapisany.
        self.assertEqual((fm.UPLOAD_DIR / "plik.pdf").read_bytes(), data)

        # DOWNLOAD — serwer wysyła chunki, składamy je z powrotem.
        self.sent.clear()
        self.feed(self.signed(C.MSG_DOWNLOAD_REQ, {"filename": "plik.pdf"}))
        chunks = [m for m in self.sent if m["type"] == C.MSG_DOWNLOAD_CHUNK]
        self.assertTrue(chunks)
        rebuilt = b"".join(base64.b64decode(m["payload"]["data"]) for m in chunks)
        self.assertEqual(rebuilt, data)
        self.assertEqual(self.conn.get_state(), C.STATE_AUTHENTICATED)


class TestListFiles(ProtocolTestBase):

    def test_list_after_upload(self):
        self.do_hello()
        self.do_auth()

        # Pusta lista na starcie.
        self.feed(self.signed(C.MSG_LIST_REQUEST, {}))
        resp = self.last()
        self.assertEqual(resp["type"], C.MSG_LIST_RESPONSE)
        self.assertEqual(resp["payload"]["files"], [])

        # Po uploadzie plik pojawia się na liście.
        data = b"dane do listy"
        checksum = hashlib.sha256(data).hexdigest()
        self.feed(self.signed(C.MSG_UPLOAD_START, {
            "filename": "lista.txt", "filesize": len(data), "checksum": checksum,
        }))
        self.feed(self.signed(C.MSG_UPLOAD_CHUNK, {
            "chunk_index": 0, "data": base64.b64encode(data).decode(),
        }))
        self.feed(self.signed(C.MSG_UPLOAD_END, {
            "filename": "lista.txt", "total_chunks": 1,
        }))

        self.feed(self.signed(C.MSG_LIST_REQUEST, {}))
        resp = self.last()
        self.assertEqual(resp["type"], C.MSG_LIST_RESPONSE)
        names = [f["filename"] for f in resp["payload"]["files"]]
        self.assertIn("lista.txt", names)

    def test_list_requires_auth(self):
        # Bez logowania (po HELLO) → UNAUTHORIZED.
        self.do_hello()
        self.feed(build_message(C.MSG_LIST_REQUEST, "", {}))
        resp = self.last()
        self.assertEqual(resp["type"], C.MSG_ERROR)
        self.assertEqual(resp["payload"]["code"], C.ERR_UNAUTHORIZED)


class TestErrorScenarios(ProtocolTestBase):

    def test_wrong_login(self):
        self.do_hello()
        resp = self.do_auth(password="zle_haslo")
        self.assertEqual(resp["type"], C.MSG_AUTH_FAIL)
        self.assertEqual(self.conn.get_state(), C.STATE_CLOSED)

    def test_unauthorized_upload_before_login(self):
        # Po HELLO (CONNECTED), ale przed AUTH — próba uploadu.
        self.do_hello()
        self.feed(build_message(C.MSG_UPLOAD_START, "", {
            "filename": "x.pdf", "filesize": 10, "checksum": "abc",
        }))
        resp = self.last()
        self.assertEqual(resp["type"], C.MSG_ERROR)
        self.assertEqual(resp["payload"]["code"], C.ERR_UNAUTHORIZED)

    def test_duplicate_message(self):
        self.do_hello()
        self.do_auth()
        ping = self.signed(C.MSG_PING, {}, msg_id="staly-msg-id")

        self.feed(ping)
        self.assertEqual(self.last()["type"], C.MSG_PONG)

        # Ta sama wiadomość po raz drugi → DUPLICATE_MESSAGE.
        self.feed(ping)
        resp = self.last()
        self.assertEqual(resp["type"], C.MSG_ERROR)
        self.assertEqual(resp["payload"]["code"], C.ERR_DUPLICATE_MESSAGE)

    def test_invalid_hmac_rejected(self):
        self.do_hello()
        self.do_auth()
        msg = self.signed(C.MSG_PING, {})
        msg["hmac"] = "0" * 64  # podmieniony podpis
        self.feed(msg)
        resp = self.last()
        self.assertEqual(resp["type"], C.MSG_ERROR)
        self.assertEqual(resp["payload"]["code"], C.ERR_INVALID_FORMAT)

    def test_invalid_json(self):
        self.handler.handle("{to nie jest poprawny json")
        resp = self.last()
        self.assertEqual(resp["type"], C.MSG_ERROR)
        self.assertEqual(resp["payload"]["code"], C.ERR_INVALID_FORMAT)

    def test_missing_required_field(self):
        # Wiadomość bez pola 'msg_id' → INVALID_FORMAT.
        broken = {
            "type": C.MSG_HELLO, "session_id": "",
            "timestamp": 1, "payload": {}, "hmac": "",
        }
        self.feed(broken)
        resp = self.last()
        self.assertEqual(resp["type"], C.MSG_ERROR)
        self.assertEqual(resp["payload"]["code"], C.ERR_INVALID_FORMAT)


if __name__ == "__main__":
    unittest.main()
