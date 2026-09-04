"""Logging foundation for USB Security Monitor.

Logs stay on the local machine. Device identifiers that may be sensitive
(for example serial numbers) should be passed through ``mask_identifier``
before they are written to a log record.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Final

_LOGGER_NAME: Final[str] = "usb_monitor"
_LOG_FORMAT: Final[str] = (
    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
)
_DATE_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S"
_MAX_LOG_BYTES: Final[int] = 1_048_576  # 1 MiB
_BACKUP_COUNT: Final[int] = 3

_configured = False


def mask_identifier(value: str | None, visible_chars: int = 4) -> str:
    """Return a partially masked identifier for safe logging.

    Examples:
        ``ABC123456789`` -> ``********6789``
        ``None`` / empty  -> ``unknown``
    """
    if not value:
        return "unknown"
    if len(value) <= visible_chars:
        return "*" * len(value)
    return f"{'*' * 8}{value[-visible_chars:]}"


def setup_logging(
    *,
    verbose: bool = False,
    quiet: bool = False,
    log_dir: Path | None = None,
) -> logging.Logger:
    """Configure console and rotating file logging once.

    Args:
        verbose: Emit DEBUG records to the console.
        quiet: Emit WARNING and above to the console.
        log_dir: Directory for ``usb_monitor.log``. Defaults to ``./logs``.
    """
    global _configured

    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.DEBUG)

    if _configured:
        return logger

    log_path = (log_dir or Path("logs")) / "usb_monitor.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=_MAX_LOG_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    if quiet:
        console_level = logging.WARNING
    elif verbose:
        console_level = logging.DEBUG
    else:
        console_level = logging.INFO
    console_handler.setLevel(console_level)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.propagate = False

    _configured = True
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child logger under the application logger namespace."""
    if not name or name == _LOGGER_NAME:
        return logging.getLogger(_LOGGER_NAME)
    if name.startswith(f"{_LOGGER_NAME}."):
        return logging.getLogger(name)
    return logging.getLogger(f"{_LOGGER_NAME}.{name}")
