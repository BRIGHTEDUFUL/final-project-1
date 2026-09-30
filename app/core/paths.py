"""Filesystem locations used by Rogue AP Hunter.

All locations are derived from environment variables so nothing is hard-coded
to a specific machine. Set ``ROGUE_AP_HUNTER_HOME`` to relocate every piece of
application data (useful for portable installs and tests).
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path

from app import APP_NAME, APP_SLUG

ENV_HOME = "ROGUE_AP_HUNTER_HOME"

__all__ = [
    "ENV_HOME",
    "app_home",
    "config_path",
    "database_path",
    "ensure_app_dirs",
    "log_dir",
    "log_file",
]


def _env(env: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if env is None else env


def app_home(env: Mapping[str, str] | None = None) -> Path:
    """Return the root directory for configuration, logs and local data."""
    environ = _env(env)

    override = environ.get(ENV_HOME, "").strip()
    if override:
        return Path(override).expanduser()

    if sys.platform == "win32":
        base = environ.get("LOCALAPPDATA") or environ.get("APPDATA")
        if not base:
            base = str(Path.home() / "AppData" / "Local")
        return Path(base) / APP_NAME

    base = environ.get("XDG_DATA_HOME")
    if base:
        return Path(base) / APP_SLUG
    return Path.home() / ".local" / "share" / APP_SLUG


def config_path(env: Mapping[str, str] | None = None) -> Path:
    """Return the path of the JSON configuration file."""
    return app_home(env) / "config.json"


def log_dir(env: Mapping[str, str] | None = None) -> Path:
    """Return the directory that receives application log files."""
    return app_home(env) / "logs"


def log_file(env: Mapping[str, str] | None = None) -> Path:
    """Return the path of the primary rotating log file."""
    return log_dir(env) / "rogue-ap-hunter.log"


def database_path(env: Mapping[str, str] | None = None) -> Path:
    """Return the path of the local SQLite database (created in Phase 3)."""
    return app_home(env) / "data" / "rogue_ap_hunter.sqlite3"


def ensure_app_dirs(env: Mapping[str, str] | None = None) -> Path:
    """Create the application directories if missing and return the home path."""
    home = app_home(env)
    home.mkdir(parents=True, exist_ok=True)
    log_dir(env).mkdir(parents=True, exist_ok=True)
    database_path(env).parent.mkdir(parents=True, exist_ok=True)
    return home
