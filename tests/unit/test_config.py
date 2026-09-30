"""Unit tests for configuration handling."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.config import (
    Config,
    ConfigError,
    RiskWeights,
    load_config,
    save_config,
)


def test_defaults_are_valid() -> None:
    Config().validate()


def test_default_values_match_documented_baseline() -> None:
    config = Config()
    assert config.scan_interval_seconds == 15
    assert (config.suspicious_threshold, config.high_threshold, config.critical_threshold) == (
        30,
        60,
        80,
    )
    weights = config.risk_weights
    assert weights.duplicate_ssid == 25
    assert weights.unknown_bssid == 20
    assert weights.security_downgrade == 30
    assert weights.new_access_point == 10
    assert weights.suspicious_signal == 5
    assert weights.persistence == 10


def test_missing_file_returns_defaults(tmp_path: Path) -> None:
    config = load_config(tmp_path / "config.json")
    assert config == Config()


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    target = tmp_path / "config.json"
    original = Config(scan_interval_seconds=30, notifications_enabled=False, log_level="DEBUG")

    save_config(original, target)
    assert load_config(target) == original
    assert not target.with_suffix(".json.tmp").exists()


def test_corrupt_json_raises_config_error(tmp_path: Path) -> None:
    target = tmp_path / "config.json"
    target.write_text("{ not json", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(target)


def test_invalid_value_raises_config_error(tmp_path: Path) -> None:
    target = tmp_path / "config.json"
    target.write_text(json.dumps({"scan_interval_seconds": 1}), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(target)


def test_unknown_keys_are_ignored(tmp_path: Path) -> None:
    target = tmp_path / "config.json"
    target.write_text(json.dumps({"scan_interval_seconds": 60, "future_option": True}), encoding="utf-8")
    assert load_config(target).scan_interval_seconds == 60


def test_threshold_order_is_enforced() -> None:
    with pytest.raises(ConfigError):
        Config(suspicious_threshold=70, high_threshold=60, critical_threshold=80).validate()


@pytest.mark.parametrize("bad_level", ["trace", "VERBOSE", ""])
def test_invalid_log_level_is_rejected(bad_level: str) -> None:
    with pytest.raises(ConfigError):
        Config(log_level=bad_level).validate()


def test_invalid_weight_is_rejected() -> None:
    with pytest.raises(ConfigError):
        Config(risk_weights=RiskWeights(duplicate_ssid=500)).validate()


def test_from_dict_rejects_non_object_root() -> None:
    with pytest.raises(ConfigError):
        Config.from_dict(["not", "a", "mapping"])  # type: ignore[arg-type]


def test_with_overrides_returns_validated_copy() -> None:
    updated = Config().with_overrides(scan_interval_seconds=45)
    assert updated.scan_interval_seconds == 45
    assert Config().scan_interval_seconds == 15
    with pytest.raises(ConfigError):
        Config().with_overrides(scan_interval_seconds=1)
