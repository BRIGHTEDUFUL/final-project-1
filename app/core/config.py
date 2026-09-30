"""Application configuration.

Configuration is stored as JSON in the per-user application directory. Loading
never raises for a missing file (defaults are returned), but a present file
that is unreadable or invalid raises :class:`ConfigError` so callers can warn
the user instead of silently discarding their settings.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

from app.core import paths

logger = logging.getLogger(__name__)

VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

MIN_SCAN_INTERVAL_SECONDS = 5
MAX_SCAN_INTERVAL_SECONDS = 3600

__all__ = [
    "Config",
    "ConfigError",
    "RiskWeights",
    "default_config_path",
    "load_config",
    "save_config",
]


class ConfigError(Exception):
    """Raised when a configuration file exists but cannot be used."""


@dataclass(frozen=True)
class RiskWeights:
    """Baseline detection weights (research parameters, see documentation §10)."""

    duplicate_ssid: int = 25
    unknown_bssid: int = 20
    security_downgrade: int = 30
    new_access_point: int = 10
    suspicious_signal: int = 5
    persistence: int = 10


@dataclass(frozen=True)
class Config:
    """Runtime configuration for the application."""

    scan_interval_seconds: int = 15
    suspicious_threshold: int = 30
    high_threshold: int = 60
    critical_threshold: int = 80
    notifications_enabled: bool = True
    frame_observer_enabled: bool = True
    data_retention_days: int = 90
    log_level: str = "INFO"
    risk_weights: RiskWeights = field(default_factory=RiskWeights)

    def validate(self) -> None:
        """Raise :class:`ConfigError` when any value is out of range."""
        if not isinstance(self.scan_interval_seconds, int) or not (
            MIN_SCAN_INTERVAL_SECONDS <= self.scan_interval_seconds <= MAX_SCAN_INTERVAL_SECONDS
        ):
            raise ConfigError(
                f"scan_interval_seconds must be between {MIN_SCAN_INTERVAL_SECONDS} and "
                f"{MAX_SCAN_INTERVAL_SECONDS}, got {self.scan_interval_seconds!r}"
            )

        thresholds = (
            self.suspicious_threshold,
            self.high_threshold,
            self.critical_threshold,
        )
        if not all(isinstance(value, int) and 0 <= value <= 100 for value in thresholds):
            raise ConfigError(f"risk thresholds must be integers within 0..100, got {thresholds!r}")
        if not (0 < self.suspicious_threshold < self.high_threshold < self.critical_threshold <= 100):
            raise ConfigError(
                "risk thresholds must satisfy 0 < suspicious < high < critical <= 100, "
                f"got {thresholds!r}"
            )

        if not isinstance(self.data_retention_days, int) or not (1 <= self.data_retention_days <= 3650):
            raise ConfigError(f"data_retention_days must be between 1 and 3650, got {self.data_retention_days!r}")

        if not isinstance(self.notifications_enabled, bool):
            raise ConfigError(f"notifications_enabled must be a boolean, got {self.notifications_enabled!r}")

        if not isinstance(self.frame_observer_enabled, bool):
            raise ConfigError(
                f"frame_observer_enabled must be a boolean, got {self.frame_observer_enabled!r}"
            )

        if self.log_level not in VALID_LOG_LEVELS:
            raise ConfigError(f"log_level must be one of {VALID_LOG_LEVELS}, got {self.log_level!r}")

        for name, value in asdict(self.risk_weights).items():
            if not isinstance(value, int) or not (0 <= value <= 100):
                raise ConfigError(f"risk weight {name} must be an integer within 0..100, got {value!r}")

    def to_dict(self) -> dict[str, Any]:
        """Serialise the configuration to a JSON-compatible dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Config:
        """Build a validated configuration from a dictionary.

        Unknown keys are ignored so that downgrading the application keeps
        previously stored settings usable.
        """
        if not isinstance(data, Mapping):
            raise ConfigError(f"configuration root must be an object, got {type(data).__name__}")

        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        unknown = sorted(set(data) - known)
        if unknown:
            logger.warning("Ignoring unknown configuration keys: %s", ", ".join(unknown))

        payload = {key: value for key, value in data.items() if key in known}
        if "risk_weights" in payload:
            weights = payload["risk_weights"]
            if not isinstance(weights, Mapping):
                raise ConfigError("risk_weights must be an object")
            payload["risk_weights"] = RiskWeights(**dict(weights))

        config = cls(**payload)
        config.validate()
        return config

    def with_overrides(self, **changes: Any) -> Config:
        """Return a validated copy with the given fields replaced."""
        updated = replace(self, **changes)
        updated.validate()
        return updated


def default_config_path() -> Path:
    """Return the default configuration file location."""
    return paths.config_path()


def load_config(path: Path | None = None) -> Config:
    """Load configuration from ``path``.

    Returns :class:`Config` defaults when the file does not exist yet.
    Raises :class:`ConfigError` when the file exists but is unreadable or invalid.
    """
    target = path or default_config_path()
    if not target.exists():
        return Config()

    try:
        raw = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read configuration file {target}: {exc}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"configuration file {target} is not valid JSON: {exc}") from exc

    try:
        return Config.from_dict(data)
    except TypeError as exc:
        raise ConfigError(f"configuration file {target} has invalid field types: {exc}") from exc


def save_config(config: Config, path: Path | None = None) -> Path:
    """Validate and write ``config`` to ``path`` atomically, returning the path."""
    config.validate()
    target = path or default_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    temporary = target.with_suffix(target.suffix + ".tmp")
    try:
        temporary.write_text(
            json.dumps(config.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(target)
    except OSError as exc:
        raise ConfigError(f"cannot write configuration file {target}: {exc}") from exc
    return target
