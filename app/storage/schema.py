"""SQLite schema definition and versioned migrations.

Schema changes are additive and versioned: :data:`SCHEMA_VERSION` is bumped in
the same commit that adds a migration, and :func:`apply_migrations` brings an
older database forward inside a single transaction.
"""

from __future__ import annotations

import sqlite3

__all__ = ["SCHEMA_VERSION", "SCHEMA_SQL", "apply_migrations", "ensure_schema"]

SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    TEXT NOT NULL,
    completed_at  TEXT,
    network_count INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid            TEXT,
    bssid           TEXT,
    signal_strength INTEGER,
    security        TEXT,
    channel         INTEGER,
    observed_at     TEXT NOT NULL,
    scan_session_id INTEGER REFERENCES scan_sessions(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS trusted_networks (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid              TEXT NOT NULL UNIQUE,
    approved_bssids   TEXT NOT NULL DEFAULT '[]',
    expected_security TEXT,
    created_at        TEXT NOT NULL,
    notes             TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid        TEXT,
    bssid       TEXT,
    alert_type  TEXT NOT NULL,
    risk_score  INTEGER NOT NULL,
    severity    TEXT NOT NULL,
    reasons     TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS risk_scores (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid       TEXT,
    bssid      TEXT,
    score      INTEGER NOT NULL,
    severity   TEXT NOT NULL,
    reasons    TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS application_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_observations_observed_at ON observations(observed_at);
CREATE INDEX IF NOT EXISTS idx_observations_bssid       ON observations(bssid);
CREATE INDEX IF NOT EXISTS idx_observations_ssid        ON observations(ssid);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at        ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_status            ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity          ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_identity          ON alerts(ssid, bssid, status);
CREATE INDEX IF NOT EXISTS idx_risk_scores_identity     ON risk_scores(ssid, bssid, created_at);
"""

# Version -> SQL executed to upgrade from the previous version.
MIGRATIONS: dict[int, str] = {
    # 1 is the baseline schema above; future versions append here, e.g.:
    # 2: "ALTER TABLE observations ADD COLUMN frequency_mhz INTEGER;",
}


def ensure_schema(connection: sqlite3.Connection) -> None:
    """Create the baseline schema if it does not exist yet."""
    connection.executescript(SCHEMA_SQL)
    row = connection.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchone()
    if row is None:
        connection.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
    connection.commit()


def apply_migrations(connection: sqlite3.Connection) -> int:
    """Bring the database up to :data:`SCHEMA_VERSION`; return the version.

    Migrations run inside one transaction: either the whole upgrade applies or
    the database is left untouched.
    """
    ensure_schema(connection)
    row = connection.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchone()
    try:
        version = int(row[0]) if row else SCHEMA_VERSION
    except (TypeError, ValueError):
        version = SCHEMA_VERSION

    if version >= SCHEMA_VERSION:
        return version

    with connection:
        for target in range(version + 1, SCHEMA_VERSION + 1):
            script = MIGRATIONS.get(target)
            if script:
                connection.executescript(script)
            connection.execute(
                "UPDATE schema_meta SET value = ? WHERE key = 'schema_version'",
                (str(target),),
            )
        version = SCHEMA_VERSION
    return version
