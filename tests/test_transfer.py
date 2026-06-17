# tests/test_transfer.py
#
# Testy transferu plików:
#  - przygotowanie i walidacja pliku po stronie klienta (client/transfer.py)
#  - składanie i weryfikacja chunków pobieranego pliku (DownloadBuffer)
#  - pełny obieg upload→zapis→download po stronie serwera (server/file_manager.py)
#
# Uruchomienie:  python -m unittest tests.test_transfer

import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

import client.transfer as transfer
import server.file_manager as fm
from shared.constants import CHUNK_SIZE_BYTES


class TestPrepareUpload(unittest.TestCase):
    """client.transfer.prepare_upload_chunks / validate_local_file."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, name: str, data: bytes) -> Path:
        p = self.dir / name
        p.write_bytes(data)
        return p

    def test_prepare_chunks_and_checksum(self):
        # Plik większy niż jeden chunk → wiele fragmentów.
        data = b"A" * (CHUNK_SIZE_BYTES * 2 + 123)
        path = self._write("dokument.txt", data)

        result = transfer.prepare_upload_chunks(str(path))
        self.assertIsNotNone(result)
        chunks, checksum, filesize, filename = result

        self.assertEqual(filename, "dokument.txt")
        self.assertEqual(filesize, len(data))
        self.assertEqual(checksum, hashlib.sha256(data).hexdigest())
        self.assertEqual(len(chunks), 3)  # 2 pełne + 1 częściowy

        # Złożenie chunków odtwarza oryginał.
        rebuilt = b"".join(base64.b64decode(c) for c in chunks)
        self.assertEqual(rebuilt, data)

    def test_reject_bad_extension(self):
        path = self._write("zlosliwy.exe", b"x")
        self.assertIsNone(transfer.prepare_upload_chunks(str(path)))

    def test_reject_missing_file(self):
        self.assertIsNone(
            transfer.prepare_upload_chunks(str(self.dir / "nie_ma.txt"))
        )

    def test_reject_empty_file(self):
        path = self._write("pusty.txt", b"")
        ok, _ = transfer.validate_local_file(path)
        self.assertFalse(ok)


class TestDownloadBuffer(unittest.TestCase):
    """client.transfer.DownloadBuffer — składanie i weryfikacja pobierania."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.b64encode(data).decode()

    def test_reassemble_and_save(self):
        data = b"czesc pierwsza|czesc druga"
        checksum = hashlib.sha256(data).hexdigest()
        buf = transfer.DownloadBuffer("plik.txt")

        c0, c1 = data[:14], data[14:]
        done, _ = buf.add_chunk(0, 2, self._b64(c0))
        self.assertFalse(done)
        # checksum dołączany przy ostatnim chunku
        done, _ = buf.add_chunk(1, 2, self._b64(c1), checksum)
        self.assertTrue(done)

        dest = self.dir / "out.txt"
        ok, err = buf.save_and_verify(str(dest))
        self.assertTrue(ok, err)
        self.assertEqual(dest.read_bytes(), data)

    def test_checksum_mismatch_rejected(self):
        buf = transfer.DownloadBuffer("plik.txt")
        buf.add_chunk(0, 1, self._b64(b"dane"), "zly_checksum")
        ok, err = buf.save_and_verify(str(self.dir / "out.txt"))
        self.assertFalse(ok)
        self.assertIn("sumy kontrolnej", err)

    def test_duplicate_chunk_rejected(self):
        buf = transfer.DownloadBuffer("plik.txt")
        buf.add_chunk(0, 2, self._b64(b"a"))
        _, err = buf.add_chunk(0, 2, self._b64(b"a"))
        self.assertIn("Zduplikowany", err)

    def test_incomplete_download_not_saved(self):
        buf = transfer.DownloadBuffer("plik.txt")
        buf.add_chunk(0, 2, self._b64(b"a"))  # brakuje chunku 1
        ok, _ = buf.save_and_verify(str(self.dir / "out.txt"))
        self.assertFalse(ok)


class TestFileManagerRoundtrip(unittest.TestCase):
    """server.file_manager — pełny obieg upload → zapis → download."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_dir = fm.UPLOAD_DIR
        fm.UPLOAD_DIR = Path(self._tmp.name) / "uploads"
        fm.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        fm._upload_buffer.clear()

    def tearDown(self):
        fm.UPLOAD_DIR = self._orig_dir
        fm._upload_buffer.clear()
        self._tmp.cleanup()

    def test_upload_then_download(self):
        data = b"X" * (CHUNK_SIZE_BYTES + 50)
        checksum = hashlib.sha256(data).hexdigest()

        ok, err = fm.upload_start("raport.pdf", len(data), checksum, "alice")
        self.assertTrue(ok, err)

        # Dwa chunki (pełny + reszta).
        c0 = data[:CHUNK_SIZE_BYTES]
        c1 = data[CHUNK_SIZE_BYTES:]
        self.assertTrue(fm.upload_chunk("raport.pdf", 0, base64.b64encode(c0).decode())[0])
        self.assertTrue(fm.upload_chunk("raport.pdf", 1, base64.b64encode(c1).decode())[0])

        ok, err = fm.upload_end("raport.pdf", 2)
        self.assertTrue(ok, err)

        # Plik na dysku ma poprawną zawartość i checksum.
        self.assertTrue(fm.file_exists("raport.pdf"))
        self.assertEqual((fm.UPLOAD_DIR / "raport.pdf").read_bytes(), data)
        self.assertEqual(fm.get_file_checksum("raport.pdf"), checksum)

        # Download odtwarza identyczne dane.
        chunks, err = fm.download_prepare("raport.pdf")
        self.assertIsNotNone(chunks, err)
        rebuilt = b"".join(base64.b64decode(c) for c in chunks)
        self.assertEqual(rebuilt, data)

    def test_upload_rejects_path_traversal(self):
        # Dozwolone rozszerzenie, ale próba wyjścia z katalogu uploads.
        ok, err = fm.upload_start("../tajne.txt", 10, "x", "alice")
        self.assertFalse(ok)
        self.assertIn("path traversal", err)

    def test_upload_end_detects_corruption(self):
        data = b"oryginal"
        good_checksum = hashlib.sha256(data).hexdigest()
        fm.upload_start("plik.txt", len(data), good_checksum, "alice")
        # Wgrywamy INNE dane niż zadeklarowany checksum.
        fm.upload_chunk("plik.txt", 0, base64.b64encode(b"podmiana").decode())
        ok, err = fm.upload_end("plik.txt", 1)
        self.assertFalse(ok)
        self.assertIn("Checksum", err)

    def test_download_missing_file(self):
        chunks, err = fm.download_prepare("nie_istnieje.txt")
        self.assertIsNone(chunks)
        self.assertIn("nie istnieje", err)


if __name__ == "__main__":
    unittest.main()
