"""Local SQLite persistence for observations, alerts, profiles and settings.

Usage::

    with Database(path) as db:
        observations = ObservationRepository(db)
        observations.add(observation)

All statements are parameterised; no caller-built SQL reaches the database.
"""

from __future__ import annotations

from app.storage.database import Database, StorageError
from app.storage.repositories import (
    AlertRepository,
    ObservationRepository,
    RiskScoreRepository,
    ScanSessionRepository,
    SettingRepository,
    TrustedNetworkRepository,
)
from app.storage.schema import SCHEMA_VERSION, apply_migrations, ensure_schema

__all__ = [
    "SCHEMA_VERSION",
    "AlertRepository",
    "Database",
    "ObservationRepository",
    "RiskScoreRepository",
    "ScanSessionRepository",
    "SettingRepository",
    "StorageError",
    "TrustedNetworkRepository",
    "apply_migrations",
    "ensure_schema",
]
