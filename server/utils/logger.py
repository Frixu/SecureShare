# server/utils/logger.py

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler

LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "secureshare.log"

MAX_BYTES   = 5 * 1024 * 1024   # 5 MB na plik
BACKUP_COUNT = 3                 # max 3 pliki rotacji


def _ensure_log_dir() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def get_logger(name: str, level: int = logging.DEBUG) -> logging.Logger:
    """
    Zwraca skonfigurowany logger.
    - konsola: INFO+
    - plik:    DEBUG+ (z rotacją)
    """
    _ensure_log_dir()

    logger = logging.getLogger(name)

    # Nie dodawaj handlerów jeśli logger już istnieje (np. przy reimporcie)
    if logger.handlers:
        return logger

    logger.setLevel(level)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)-24s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Handler konsolowy
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    # Handler plikowy z rotacją
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger


# ---------- Pomocnicze loggery dla warstw serwera ----------

def get_server_logger()   -> logging.Logger: return get_logger("server.main")
def get_auth_logger()     -> logging.Logger: return get_logger("server.auth")
def get_transfer_logger() -> logging.Logger: return get_logger("server.transfer")
def get_crypto_logger()   -> logging.Logger: return get_logger("server.crypto")
def get_protocol_logger() -> logging.Logger: return get_logger("server.protocol")