"""Unit tests for path resolution."""

from __future__ import annotations

from pathlib import Path

from app import APP_NAME, APP_SLUG
from app.core import paths


def test_home_override_env_wins() -> None:
    home = paths.app_home({paths.ENV_HOME: str(Path("C:/portable/data"))})
    assert home == Path("C:/portable/data")


def test_home_falls_back_to_platform_default() -> None:
    home = paths.app_home({})
    assert home.name in {APP_NAME, APP_SLUG}


def test_xdg_data_home_is_used_on_posix(monkeypatch) -> None:
    monkeypatch.setattr(paths.sys, "platform", "linux")
    home = paths.app_home({"XDG_DATA_HOME": "/home/user/.share"})
    assert home == Path("/home/user/.share") / APP_SLUG


def test_locations_are_derived_from_home() -> None:
    env = {paths.ENV_HOME: "/tmp/rogue-home"}
    assert paths.config_path(env) == Path("/tmp/rogue-home") / "config.json"
    assert paths.log_dir(env) == Path("/tmp/rogue-home") / "logs"
    assert paths.database_path(env) == Path("/tmp/rogue-home") / "data" / "rogue_ap_hunter.sqlite3"


def test_ensure_app_dirs_creates_directories(tmp_path: Path) -> None:
    env = {paths.ENV_HOME: str(tmp_path / "home")}
    home = paths.ensure_app_dirs(env)
    assert home.is_dir()
    assert paths.log_dir(env).is_dir()
    assert paths.database_path(env).parent.is_dir()


def test_asset_path_points_at_the_shipped_assets() -> None:
    icon = paths.asset_path("icon.png")
    assert icon.parent.name == "assets"
    assert icon.is_file(), "the application icon must ship with the repository"
