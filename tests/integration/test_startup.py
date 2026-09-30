"""Integration tests: the application starts, reports status and exits cleanly."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from app import VERSION
from app.core.logging_setup import setup_logging
from app.main import EXIT_GUI_UNAVAILABLE, EXIT_OK, main


@pytest.fixture()
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect every application path into a temporary directory."""
    from app.core import paths

    target = tmp_path / "home"
    monkeypatch.setenv(paths.ENV_HOME, str(target))
    return target


def test_headless_start_exits_cleanly(home: Path) -> None:
    assert main(["--headless"]) == EXIT_OK
    assert home.is_dir()
    assert (home / "logs").is_dir()


def test_version_flag_prints_version(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert VERSION in capsys.readouterr().out


def test_write_default_config_creates_valid_file(home: Path) -> None:
    assert main(["--write-default-config"]) == EXIT_OK
    config_file = home / "config.json"
    assert config_file.is_file()
    data = json.loads(config_file.read_text(encoding="utf-8"))
    assert data["scan_interval_seconds"] == 15
    assert data["risk_weights"]["duplicate_ssid"] == 25


def test_explicit_config_path_is_used(tmp_path: Path) -> None:
    target = tmp_path / "custom" / "settings.json"
    assert main(["--headless", "--config", str(target), "--log-level", "WARNING"]) == EXIT_OK
    assert target.parent.is_dir()


def test_corrupt_config_does_not_crash_startup(tmp_path: Path) -> None:
    target = tmp_path / "broken.json"
    target.write_text("{{{{", encoding="utf-8")
    assert main(["--headless", "--config", str(target)]) == EXIT_OK


def test_gui_exit_code_when_interface_unavailable(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without PySide6 installed the launcher must fail gracefully, not crash."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object):
        if name == "app.ui.shell":
            raise ImportError("PySide6 is not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert main([]) == EXIT_GUI_UNAVAILABLE


def test_logging_setup_is_idempotent(tmp_path: Path) -> None:
    log_dir = tmp_path / "logs"
    setup_logging("INFO", log_dir, force=True)
    handlers_first = list(logging.getLogger().handlers)
    setup_logging("DEBUG", log_dir)
    handlers_second = list(logging.getLogger().handlers)

    assert handlers_first
    assert len(handlers_second) == len(handlers_first)
    logging.getLogger("app.test").info("message after reconfiguration")
    assert (log_dir / "rogue-ap-hunter.log").exists()


def test_logging_rejects_unknown_level(tmp_path: Path) -> None:
    from app.core.config import ConfigError

    with pytest.raises(ConfigError):
        setup_logging("NOPE", tmp_path / "logs", force=True)
