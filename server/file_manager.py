# server/file_manager.py

import base64
import hashlib
import shutil
from pathlib import Path
from typing import Optional

from server.utils.crypto import compute_file_checksum, verify_file_checksum
from server.utils.logger import get_transfer_logger
from shared.constants import MAX_FILE_SIZE_BYTES, CHUNK_SIZE_BYTES

logger = get_transfer_logger()

UPLOAD_DIR = Path("uploads")
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".docx", ".png", ".jpg"}


# ---------- Inicjalizacja ----------

def init_storage() -> None:
    """Tworzy katalog uploads jeśli nie istnieje."""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Storage zainicjalizowany: {UPLOAD_DIR.resolve()}")


# ---------- Walidacja ----------

def _validate_filename(filename: str) -> tuple[bool, str]:
    p = Path(filename)
    if not p.suffix.lower() in ALLOWED_EXTENSIONS:
        return False, f"Niedozwolone rozszerzenie: '{p.suffix}'"
    if "/" in filename or "\\" in filename or ".." in filename:
        return False, "Niedozwolona nazwa pliku (path traversal)"
    if len(filename) > 255:
        return False, "Nazwa pliku zbyt długa"
    return True, ""


def _validate_filesize(size: int) -> tuple[bool, str]:
    if size <= 0:
        return False, "Rozmiar pliku musi być > 0"
    if size > MAX_FILE_SIZE_BYTES:
        mb = MAX_FILE_SIZE_BYTES // (1024 * 1024)
        return False, f"Plik zbyt duży (max {mb} MB)"
    return True, ""


# ---------- Upload ----------

# Bufor tymczasowy dla trwających uploadów:
# { filename: { "chunks": {index: bytes}, "total_size": int, "checksum": str, "username": str } }
_upload_buffer: dict[str, dict] = {}


def upload_start(filename: str, filesize: int, checksum: str, username: str) -> tuple[bool, str]:
    """Inicjuje upload pliku. Zwraca (ok, error_msg)."""
    ok, err = _validate_filename(filename)
    if not ok:
        return False, err

    ok, err = _validate_filesize(filesize)
    if not ok:
        return False, err

    _upload_buffer[filename] = {
        "chunks":     {},
        "total_size": filesize,
        "checksum":   checksum,
        "username":   username,
    }
    logger.info(f"Upload start | file='{filename}' | size={filesize}B | user='{username}'")
    return True, ""


def upload_chunk(filename: str, chunk_index: int, data_b64: str) -> tuple[bool, str]:
    """Przyjmuje chunk pliku (dane jako base64). Zwraca (ok, error_msg)."""
    if filename not in _upload_buffer:
        return False, f"Brak aktywnego uploadu dla '{filename}'"

    try:
        chunk_data = base64.b64decode(data_b64)
    except Exception:
        return False, "Nieprawidłowe dane base64 w chunku"

    if len(chunk_data) > CHUNK_SIZE_BYTES * 2:
        return False, "Chunk zbyt duży"

    _upload_buffer[filename]["chunks"][chunk_index] = chunk_data
    logger.debug(f"Upload chunk | file='{filename}' | chunk={chunk_index} | size={len(chunk_data)}B")
    return True, ""


def upload_end(filename: str, total_chunks: int) -> tuple[bool, str]:
    """
    Finalizuje upload: składa chunki, weryfikuje checksum, zapisuje plik.
    Zwraca (ok, error_msg).
    """
    if filename not in _upload_buffer:
        return False, f"Brak aktywnego uploadu dla '{filename}'"

    buf = _upload_buffer[filename]
    chunks = buf["chunks"]

    # Sprawdź czy mamy wszystkie chunki
    missing = [i for i in range(total_chunks) if i not in chunks]
    if missing:
        return False, f"Brakujące chunki: {missing}"

    # Złóż plik
    file_data = b"".join(chunks[i] for i in range(total_chunks))

    # Weryfikuj rozmiar
    if len(file_data) != buf["total_size"]:
        return False, (
            f"Rozmiar pliku niezgodny: oczekiwano {buf['total_size']}B, "
            f"otrzymano {len(file_data)}B"
        )

    # Weryfikuj checksum
    if not verify_file_checksum(file_data, buf["checksum"]):
        return False, "Checksum pliku niezgodny — plik uszkodzony lub zmodyfikowany"

    # Zapisz plik
    dest = UPLOAD_DIR / filename
    dest.write_bytes(file_data)

    del _upload_buffer[filename]
    logger.info(
        f"Upload zakończony | file='{filename}' | "
        f"size={len(file_data)}B | user='{buf['username']}'"
    )
    return True, ""


def abort_upload(filename: str) -> None:
    """Czyści bufor dla przerwanego uploadu."""
    if filename in _upload_buffer:
        del _upload_buffer[filename]
        logger.warning(f"Upload przerwany | file='{filename}'")


# ---------- Download ----------

def download_prepare(filename: str) -> tuple[Optional[list[str]], str]:
    """
    Przygotowuje plik do pobrania — dzieli na chunki zakodowane w base64.
    Zwraca (lista_chunków_b64, error_msg).
    """
    ok, err = _validate_filename(filename)
    if not ok:
        return None, err

    path = UPLOAD_DIR / filename
    if not path.exists():
        return None, f"Plik '{filename}' nie istnieje na serwerze"

    file_data = path.read_bytes()
    chunks = []
    for i in range(0, len(file_data), CHUNK_SIZE_BYTES):
        chunk = file_data[i : i + CHUNK_SIZE_BYTES]
        chunks.append(base64.b64encode(chunk).decode())

    logger.info(
        f"Download przygotowany | file='{filename}' | "
        f"chunks={len(chunks)} | size={len(file_data)}B"
    )
    return chunks, ""


def get_file_checksum(filename: str) -> Optional[str]:
    """Zwraca SHA-256 checksum pliku z dysku, lub None jeśli plik nie istnieje."""
    path = UPLOAD_DIR / filename
    if not path.exists():
        return None
    return compute_file_checksum(path.read_bytes())


# ---------- Listowanie plików ----------

def list_files() -> list[dict]:
    """Zwraca listę plików w storage z metadanymi."""
    if not UPLOAD_DIR.exists():
        return []
    result = []
    for f in sorted(UPLOAD_DIR.iterdir()):
        if f.is_file():
            result.append({
                "filename": f.name,
                "size":     f.stat().st_size,
                "checksum": compute_file_checksum(f.read_bytes()),
            })
    return result


def file_exists(filename: str) -> bool:
    return (UPLOAD_DIR / filename).exists()