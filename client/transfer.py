# client/transfer.py

import base64
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from client.utils.logger import get_transfer_logger
from shared.constants import MAX_FILE_SIZE_BYTES, CHUNK_SIZE_BYTES

logger = get_transfer_logger()

ALLOWED_EXTENSIONS = {".pdf", ".txt", ".docx", ".png", ".jpg"}


def validate_local_file(filepath: Path) -> Tuple[bool, str]:
    """Validates if the local file exists, is a file, has allowed extension, and size."""
    if not filepath.exists():
        return False, f"Plik '{filepath}' nie istnieje."
    if not filepath.is_file():
        return False, f"Ścieżka '{filepath}' nie wskazuje na plik."
    if filepath.suffix.lower() not in ALLOWED_EXTENSIONS:
        return False, f"Niedozwolone rozszerzenie pliku: '{filepath.suffix}'. Dozwolone: {ALLOWED_EXTENSIONS}"
    
    size = filepath.stat().st_size
    if size <= 0:
        return False, "Rozmiar pliku musi być większy niż 0 bajtów."
    if size > MAX_FILE_SIZE_BYTES:
        mb = MAX_FILE_SIZE_BYTES // (1024 * 1024)
        return False, f"Plik jest zbyt duży (maksymalnie {mb} MB)."
    
    return True, ""


def prepare_upload_chunks(filepath_str: str) -> Optional[Tuple[List[str], str, int, str]]:
    """
    Reads a local file, calculates SHA-256, and splits it into 8KB base64 chunks.
    Returns (chunks_b64, checksum, filesize, filename) or None on failure.
    """
    filepath = Path(filepath_str)
    ok, err = validate_local_file(filepath)
    if not ok:
        logger.error(err)
        return None

    try:
        data = filepath.read_bytes()
    except OSError as e:
        logger.error(f"Nie udało się odczytać pliku: {e}")
        return None

    checksum = hashlib.sha256(data).hexdigest()
    filesize = len(data)
    filename = filepath.name

    chunks_b64 = []
    for i in range(0, filesize, CHUNK_SIZE_BYTES):
        chunk = data[i : i + CHUNK_SIZE_BYTES]
        chunks_b64.append(base64.b64encode(chunk).decode("utf-8"))

    logger.info(
        f"Przygotowano plik '{filename}' do wysłania | "
        f"rozmiar: {filesize}B, fragmenty: {len(chunks_b64)}, checksum: {checksum[:8]}..."
    )
    return chunks_b64, checksum, filesize, filename


class DownloadBuffer:
    """Helper class to collect, reassemble, and verify chunks during download."""

    def __init__(self, filename: str, expected_checksum: str = ""):
        self.filename = filename
        self.expected_checksum = expected_checksum
        self.chunks: Dict[int, bytes] = {}
        self.total_chunks: Optional[int] = None

    def add_chunk(self, chunk_index: int, total_chunks: int, data_b64: str, checksum: str = "") -> Tuple[bool, str]:
        """Adds a chunk to the buffer. Returns (is_complete, status_msg)."""
        if self.total_chunks is None:
            self.total_chunks = total_chunks
        elif self.total_chunks != total_chunks:
            return False, "Niezgodność całkowitej liczby fragmentów pliku."

        if chunk_index in self.chunks:
            return False, f"Zduplikowany fragment o indeksie {chunk_index}."

        try:
            chunk_data = base64.b64decode(data_b64.encode("utf-8"))
        except Exception:
            return False, "Błąd dekodowania base64 dla fragmentu."

        self.chunks[chunk_index] = chunk_data
        
        if checksum:
            self.expected_checksum = checksum

        is_complete = len(self.chunks) == self.total_chunks
        return is_complete, ""

    def save_and_verify(self, dest_path_str: str) -> Tuple[bool, str]:
        """Reassembles the chunks, verifies checksum, and saves to file."""
        if self.total_chunks is None or len(self.chunks) != self.total_chunks:
            return False, "Nie wszystkie fragmenty zostały pobrane."

        # Reassemble
        file_data = b"".join(self.chunks[i] for i in range(self.total_chunks))

        # Verify checksum
        if self.expected_checksum:
            actual_checksum = hashlib.sha256(file_data).hexdigest()
            if actual_checksum != self.expected_checksum:
                return False, (
                    f"Błąd sumy kontrolnej pobranego pliku!\n"
                    f"  Oczekiwano: {self.expected_checksum}\n"
                    f"  Otrzymano:  {actual_checksum}"
                )

        dest_path = Path(dest_path_str)
        try:
            # Create parents if they don't exist
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            dest_path.write_bytes(file_data)
            logger.info(f"Plik '{self.filename}' został zapisany pomyślnie w '{dest_path.resolve()}'")
            return True, ""
        except OSError as e:
            return False, f"Błąd zapisu pliku na dysku: {e}"
