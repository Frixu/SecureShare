# client/utils/logger.py

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler

LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "secureshare_client.log"

MAX_BYTES   = 5 * 1024 * 1024   # 5 MB
BACKUP_COUNT = 3                 # max 3 rotated files


def _ensure_log_dir() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def get_logger(name: str, level: int = logging.DEBUG) -> logging.Logger:
    """
    Returns a configured logger:
    - console: INFO+
    - file:    DEBUG+ (with rotation)
    """
    _ensure_log_dir()

    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(level)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)-24s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    # File handler with rotation
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


def get_client_logger() -> logging.Logger:
    return get_logger("client.main")


def get_transfer_logger() -> logging.Logger:
    return get_logger("client.transfer")


def get_protocol_logger() -> logging.Logger:
    return get_logger("client.protocol")
