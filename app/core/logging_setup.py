"""Logging bootstrap: console plus a rotating local log file.

The setup is idempotent so repeated calls (for example during tests or a
monitoring restart) never stack duplicate handlers.
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from app.core import paths
from app.core.config import VALID_LOG_LEVELS, ConfigError

LOGGER_NAME = "app"
LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_LOG_BYTES = 1_000_000
LOG_BACKUP_COUNT = 3

__all__ = ["setup_logging"]

_CONFIGURED_FLAG = "_rogue_ap_hunter_configured"


def _resolve_level(level: str | int) -> int:
    if isinstance(level, int):
        return level
    normalised = str(level).upper()
    if normalised not in VALID_LOG_LEVELS:
        raise ConfigError(f"log_level must be one of {VALID_LOG_LEVELS}, got {level!r}")
    return getattr(logging, normalised)


def setup_logging(
    level: str | int = "INFO",
    log_dir: Path | None = None,
    *,
    console: bool = True,
    file: bool = True,
    force: bool = False,
) -> None:
    """Configure the root logger for the application.

    Parameters
    ----------
    level:
        Logging level name or numeric value.
    log_dir:
        Directory for the rotating log file. When ``None``, the per-user
        application log directory is used.
    console:
        Attach a stream handler to ``stderr``.
    file:
        Attach the rotating file handler. When the directory cannot be created
        the file handler is skipped and a warning is logged instead.
    force:
        Re-configure even if logging was already initialised.
    """
    resolved = _resolve_level(level)
    root = logging.getLogger()

    if getattr(root, _CONFIGURED_FLAG, False) and not force:
        root.setLevel(resolved)
        for handler in root.handlers:
            handler.setLevel(resolved)
        return

    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()

    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
    root.setLevel(resolved)

    if console:
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        stream.setLevel(resolved)
        root.addHandler(stream)

    if file:
        directory = Path(log_dir) if log_dir is not None else paths.log_dir()
        try:
            directory.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                directory / "rogue-ap-hunter.log",
                maxBytes=MAX_LOG_BYTES,
                backupCount=LOG_BACKUP_COUNT,
                encoding="utf-8",
            )
        except OSError as exc:
            root.warning("File logging disabled, cannot open log directory %s: %s", directory, exc)
        else:
            file_handler.setFormatter(formatter)
            file_handler.setLevel(resolved)
            root.addHandler(file_handler)

    setattr(root, _CONFIGURED_FLAG, True)
