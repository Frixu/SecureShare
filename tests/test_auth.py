# tests/test_auth.py
#
# Testy warstwy bezpieczeństwa: kryptografia (hasła, HMAC, checksum)
# oraz uwierzytelnianie i sesje.
#
# Uruchomienie:  python -m unittest tests.test_auth   (z katalogu projektu)

import tempfile
import unittest
from pathlib import Path

import server.auth as auth
from server.utils import crypto


class TestCrypto(unittest.TestCase):
    """Funkcje kryptograficzne z server/utils/crypto.py."""

    def test_password_hash_roundtrip(self):
        stored = crypto.hash_password("haslo123")
        self.assertIn(":", stored)  # format 'salt:hash'
        self.assertTrue(crypto.verify_password("haslo123", stored))
        self.assertFalse(crypto.verify_password("zle_haslo", stored))

    def test_password_uses_random_salt(self):
        # To samo hasło → różne hashe (losowy salt).
        self.assertNotEqual(
            crypto.hash_password("x"),
            crypto.hash_password("x"),
        )

    def test_verify_password_malformed_stored(self):
        # Brak ':' w zapisanym haszu nie może rzucać wyjątku.
        self.assertFalse(crypto.verify_password("x", "brak-dwukropka"))

    def test_hmac_roundtrip(self):
        secret = crypto.generate_hmac_secret()
        msg = {
            "type": "PING", "session_id": "s", "msg_id": "m",
            "timestamp": 1, "payload": {}, "hmac": "",
        }
        msg["hmac"] = crypto.compute_hmac(msg, secret)
        self.assertTrue(crypto.verify_hmac(msg, secret))

    def test_hmac_detects_tampering(self):
        secret = crypto.generate_hmac_secret()
        msg = {
            "type": "PING", "session_id": "s", "msg_id": "m",
            "timestamp": 1, "payload": {}, "hmac": "",
        }
        msg["hmac"] = crypto.compute_hmac(msg, secret)
        msg["payload"] = {"zmiana": True}  # modyfikacja po podpisaniu
        self.assertFalse(crypto.verify_hmac(msg, secret))

    def test_hmac_wrong_secret(self):
        msg = {
            "type": "PING", "session_id": "s", "msg_id": "m",
            "timestamp": 1, "payload": {}, "hmac": "",
        }
        msg["hmac"] = crypto.compute_hmac(msg, b"klucz-A" * 4)
        self.assertFalse(crypto.verify_hmac(msg, b"klucz-B" * 4))

    def test_file_checksum(self):
        data = b"zawartosc pliku"
        chk = crypto.compute_file_checksum(data)
        self.assertTrue(crypto.verify_file_checksum(data, chk))
        self.assertFalse(crypto.verify_file_checksum(b"inna zawartosc", chk))


class TestAuth(unittest.TestCase):
    """Rejestracja, logowanie i zarządzanie sesjami (server/auth.py)."""

    def setUp(self):
        # Izolacja: tymczasowy plik users.json i czyste sesje.
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_users_file = auth.USERS_FILE
        auth.USERS_FILE = Path(self._tmp.name) / "users.json"
        auth._active_sessions.clear()

    def tearDown(self):
        auth.USERS_FILE = self._orig_users_file
        auth._active_sessions.clear()
        self._tmp.cleanup()

    def test_register_user(self):
        self.assertTrue(auth.register_user("alice", "pw"))
        self.assertTrue(auth.user_exists("alice"))

    def test_register_duplicate_user(self):
        self.assertTrue(auth.register_user("alice", "pw"))
        self.assertFalse(auth.register_user("alice", "inne"))  # już istnieje

    def test_authenticate_success(self):
        auth.register_user("alice", "haslo123")
        result = auth.authenticate("alice", "haslo123")
        self.assertIsNotNone(result)
        session_id, secret = result
        self.assertTrue(auth.is_authenticated(session_id))
        self.assertEqual(auth.get_username(session_id), "alice")
        self.assertEqual(auth.get_hmac_secret(session_id), secret)

    def test_authenticate_wrong_password(self):
        auth.register_user("bob", "poprawne")
        self.assertIsNone(auth.authenticate("bob", "bledne"))

    def test_authenticate_unknown_user(self):
        self.assertIsNone(auth.authenticate("nieistnieje", "x"))

    def test_invalidate_session(self):
        auth.register_user("carol", "pw")
        session_id, _ = auth.authenticate("carol", "pw")
        self.assertTrue(auth.is_authenticated(session_id))
        auth.invalidate_session(session_id)
        self.assertFalse(auth.is_authenticated(session_id))
        self.assertIsNone(auth.get_hmac_secret(session_id))

    def test_sessions_are_unique(self):
        auth.register_user("dave", "pw")
        s1, _ = auth.authenticate("dave", "pw")
        s2, _ = auth.authenticate("dave", "pw")
        self.assertNotEqual(s1, s2)


if __name__ == "__main__":
    unittest.main()
