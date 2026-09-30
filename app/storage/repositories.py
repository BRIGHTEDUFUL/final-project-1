"""Repository classes: parameterised persistence for each domain model.

Every method uses bound parameters and returns plain domain models, so the
rest of the application never writes SQL itself.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from app.models import (
    Alert,
    AlertStatus,
    AlertType,
    ApplicationSetting,
    NetworkObservation,
    ScanSession,
    ScanSessionStatus,
    Severity,
    TrustedNetwork,
    utcnow,
)
from app.storage.database import Database, StorageError

logger = logging.getLogger(__name__)

__all__ = [
    "AlertRepository",
    "ObservationRepository",
    "RiskScoreRepository",
    "ScanSessionRepository",
    "SettingRepository",
    "TrustedNetworkRepository",
]


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


class ScanSessionRepository:
    """Persistence for scan session lifecycle records."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def start(self, started_at: datetime | None = None) -> ScanSession:
        """Insert a running session and return it with its identifier."""
        session = ScanSession(started_at=started_at or utcnow())
        cursor = self._db.execute(
            "INSERT INTO scan_sessions (started_at, completed_at, network_count, status) "
            "VALUES (?, ?, ?, ?)",
            (_iso(session.started_at), None, session.network_count, session.status.value),
        )
        return ScanSession(
            id=cursor.lastrowid,
            started_at=session.started_at,
            network_count=session.network_count,
            status=session.status,
        )

    def finish(
        self,
        session: ScanSession,
        *,
        network_count: int | None = None,
        status: ScanSessionStatus = ScanSessionStatus.COMPLETED,
        completed_at: datetime | None = None,
    ) -> ScanSession:
        """Persist the terminal state of a session."""
        if session.id is None:
            raise StorageError("cannot finish a session that was never stored")
        finished = session.finish(status, network_count=network_count, completed_at=completed_at)
        self._db.execute(
            "UPDATE scan_sessions SET completed_at = ?, network_count = ?, status = ? WHERE id = ?",
            (_iso(finished.completed_at), finished.network_count, finished.status.value, session.id),
        )
        return finished

    def recent(self, limit: int = 50) -> list[ScanSession]:
        """Return the most recent sessions, newest first."""
        rows = self._db.query(
            "SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT ?",
            (max(1, int(limit)),),
        )
        return [self._to_model(row) for row in rows]

    def count(self) -> int:
        """Total number of recorded sessions."""
        row = self._db.query_one("SELECT COUNT(*) AS n FROM scan_sessions")
        return int(row["n"]) if row else 0

    @staticmethod
    def _to_model(row: Any) -> ScanSession:
        return ScanSession.from_dict(dict(row))


class ObservationRepository:
    """Persistence for network observations."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def add(self, observation: NetworkObservation, *, session_id: int | None = None) -> NetworkObservation:
        """Store one observation and return it with its identifier."""
        cursor = self._db.execute(
            "INSERT INTO observations "
            "(ssid, bssid, signal_strength, security, channel, observed_at, scan_session_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                observation.ssid,
                observation.bssid,
                observation.signal_strength,
                observation.security,
                observation.channel,
                _iso(observation.observed_at),
                session_id,
            ),
        )
        return NetworkObservation(
            id=cursor.lastrowid,
            ssid=observation.ssid,
            bssid=observation.bssid,
            signal_strength=observation.signal_strength,
            security=observation.security,
            channel=observation.channel,
            observed_at=observation.observed_at,
        )

    def add_many(
        self,
        observations: list[NetworkObservation],
        *,
        session_id: int | None = None,
    ) -> int:
        """Store many observations in one transaction; return the count stored."""
        if not observations:
            return 0
        with self._db.transaction() as connection:
            connection.executemany(
                "INSERT INTO observations "
                "(ssid, bssid, signal_strength, security, channel, observed_at, scan_session_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        item.ssid,
                        item.bssid,
                        item.signal_strength,
                        item.security,
                        item.channel,
                        _iso(item.observed_at),
                        session_id,
                    )
                    for item in observations
                ],
            )
        return len(observations)

    def recent(self, limit: int = 100) -> list[NetworkObservation]:
        """Newest observations first."""
        rows = self._db.query(
            "SELECT * FROM observations ORDER BY observed_at DESC, id DESC LIMIT ?",
            (max(1, int(limit)),),
        )
        return [self._to_model(row) for row in rows]

    def for_bssid(self, bssid: str, limit: int = 200) -> list[NetworkObservation]:
        """Observations for one radio, newest first."""
        rows = self._db.query(
            "SELECT * FROM observations WHERE bssid = ? ORDER BY observed_at DESC LIMIT ?",
            (bssid, max(1, int(limit))),
        )
        return [self._to_model(row) for row in rows]

    def for_ssid(self, ssid: str, limit: int = 200) -> list[NetworkObservation]:
        """Observations for one network name, newest first."""
        rows = self._db.query(
            "SELECT * FROM observations WHERE ssid = ? ORDER BY observed_at DESC LIMIT ?",
            (ssid, max(1, int(limit))),
        )
        return [self._to_model(row) for row in rows]

    def latest_for(self, *, ssid: str | None = None, bssid: str | None = None) -> NetworkObservation | None:
        """Most recent observation matching the given identity parts."""
        clauses: list[str] = []
        parameters: list[object] = []
        if ssid is not None:
            clauses.append("ssid = ?")
            parameters.append(ssid)
        if bssid is not None:
            clauses.append("bssid = ?")
            parameters.append(bssid)
        if not clauses:
            return None
        row = self._db.query_one(
            f"SELECT * FROM observations WHERE {' AND '.join(clauses)} "  # noqa: S608 - clauses are literals
            "ORDER BY observed_at DESC, id DESC LIMIT 1",
            tuple(parameters),
        )
        return self._to_model(row) if row else None

    def count(self) -> int:
        """Total observations stored."""
        row = self._db.query_one("SELECT COUNT(*) AS n FROM observations")
        return int(row["n"]) if row else 0

    def known_bssids(self) -> frozenset[str]:
        """Every BSSID recorded so far (used by the new-access-point rule)."""
        rows = self._db.query("SELECT DISTINCT bssid FROM observations WHERE bssid IS NOT NULL")
        return frozenset(str(row["bssid"]) for row in rows if row["bssid"])

    def known_ssids(self) -> frozenset[str]:
        """Every network name recorded so far."""
        rows = self._db.query("SELECT DISTINCT ssid FROM observations WHERE ssid IS NOT NULL")
        return frozenset(str(row["ssid"]) for row in rows if row["ssid"])

    def prune(self, older_than: datetime) -> int:
        """Delete observations older than ``older_than``; return rows removed."""
        cursor = self._db.execute("DELETE FROM observations WHERE observed_at < ?", (_iso(older_than),))
        return cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0

    @staticmethod
    def _to_model(row: Any) -> NetworkObservation:
        return NetworkObservation.from_dict(dict(row))


class TrustedNetworkRepository:
    """Persistence for trusted network profiles."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def upsert(self, profile: TrustedNetwork) -> TrustedNetwork:
        """Insert or update a profile by SSID and return the stored version."""
        with self._db.transaction() as connection:
            connection.execute(
                "INSERT INTO trusted_networks "
                "(ssid, approved_bssids, expected_security, created_at, notes) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(ssid) DO UPDATE SET "
                "approved_bssids = excluded.approved_bssids, "
                "expected_security = excluded.expected_security, "
                "notes = excluded.notes",
                (
                    profile.ssid,
                    json.dumps(list(profile.approved_bssids)),
                    profile.expected_security,
                    _iso(profile.created_at),
                    profile.notes,
                ),
            )
            row = connection.execute(
                "SELECT * FROM trusted_networks WHERE ssid = ?", (profile.ssid,)
            ).fetchone()
        return self._to_model(row)

    def list(self) -> list[TrustedNetwork]:
        """All profiles ordered by name."""
        rows = self._db.query("SELECT * FROM trusted_networks ORDER BY ssid COLLATE NOCASE")
        return [self._to_model(row) for row in rows]

    def get_by_ssid(self, ssid: str) -> TrustedNetwork | None:
        """Look up a single profile by its network name."""
        row = self._db.query_one("SELECT * FROM trusted_networks WHERE ssid = ?", (ssid,))
        return self._to_model(row) if row else None

    def delete(self, profile_id: int) -> bool:
        """Delete a profile by identifier; return whether anything was removed."""
        cursor = self._db.execute("DELETE FROM trusted_networks WHERE id = ?", (profile_id,))
        return bool(cursor.rowcount)

    def delete_by_ssid(self, ssid: str) -> bool:
        """Delete a profile by network name."""
        cursor = self._db.execute("DELETE FROM trusted_networks WHERE ssid = ?", (ssid,))
        return bool(cursor.rowcount)

    def count(self) -> int:
        """Number of trusted profiles."""
        row = self._db.query_one("SELECT COUNT(*) AS n FROM trusted_networks")
        return int(row["n"]) if row else 0

    @staticmethod
    def _to_model(row: Any) -> TrustedNetwork:
        data = dict(row)
        data["approved_bssids"] = json.loads(data.get("approved_bssids") or "[]")
        return TrustedNetwork.from_dict(data)


class AlertRepository:
    """Persistence for alerts, including deduplication and workflow status."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def add(self, alert: Alert) -> Alert:
        """Store a new alert and return it with its identifier."""
        cursor = self._db.execute(
            "INSERT INTO alerts "
            "(ssid, bssid, alert_type, risk_score, severity, reasons, created_at, status, "
            "first_seen, last_seen, occurrence_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert.ssid,
                alert.bssid,
                alert.alert_type.value,
                alert.risk_score,
                alert.severity.value if alert.severity else Severity.LOW.value,
                json.dumps(list(alert.reasons)),
                _iso(alert.created_at),
                alert.status.value,
                _iso(alert.first_seen),
                _iso(alert.last_seen),
                alert.occurrence_count,
            ),
        )
        return Alert(
            id=cursor.lastrowid,
            ssid=alert.ssid,
            bssid=alert.bssid,
            alert_type=alert.alert_type,
            risk_score=alert.risk_score,
            severity=alert.severity,
            reasons=alert.reasons,
            created_at=alert.created_at,
            status=alert.status,
            first_seen=alert.first_seen,
            last_seen=alert.last_seen,
            occurrence_count=alert.occurrence_count,
        )

    def find_open_match(self, alert: Alert) -> Alert | None:
        """Return an open alert of the same type for the same identity, if any."""
        row = self._db.query_one(
            "SELECT * FROM alerts WHERE alert_type = ? AND status = 'active' AND "
            "COALESCE(ssid, '') = COALESCE(?, '') AND COALESCE(bssid, '') = COALESCE(?, '') "
            "ORDER BY created_at DESC LIMIT 1",
            (alert.alert_type.value, alert.ssid, alert.bssid),
        )
        return self._to_model(row) if row else None

    def record_occurrence(self, existing: Alert, alert: Alert) -> Alert:
        """Bump first/last seen (and merge evidence) on an existing open alert."""
        updated = existing.record_occurrence(alert.last_seen or alert.created_at, reasons=alert.reasons)
        if alert.risk_score > updated.risk_score:
            updated = Alert(
                id=updated.id,
                ssid=updated.ssid,
                bssid=updated.bssid,
                alert_type=updated.alert_type,
                risk_score=alert.risk_score,
                severity=alert.severity or updated.severity,
                reasons=updated.reasons,
                created_at=updated.created_at,
                status=updated.status,
                first_seen=updated.first_seen,
                last_seen=updated.last_seen,
                occurrence_count=updated.occurrence_count,
            )
        self._db.execute(
            "UPDATE alerts SET first_seen = ?, last_seen = ?, occurrence_count = ?, "
            "reasons = ?, risk_score = ?, severity = ? WHERE id = ?",
            (
                _iso(updated.first_seen),
                _iso(updated.last_seen),
                updated.occurrence_count,
                json.dumps(list(updated.reasons)),
                updated.risk_score,
                updated.severity.value if updated.severity else Severity.LOW.value,
                updated.id,
            ),
        )
        return updated

    def set_status(self, alert_id: int, status: AlertStatus) -> Alert | None:
        """Update workflow status and return the refreshed alert."""
        self._db.execute("UPDATE alerts SET status = ? WHERE id = ?", (status.value, alert_id))
        return self.get(alert_id)

    def get(self, alert_id: int) -> Alert | None:
        """Fetch one alert by identifier."""
        row = self._db.query_one("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        return self._to_model(row) if row else None

    def list(
        self,
        *,
        status: AlertStatus | None = None,
        severity: Severity | None = None,
        alert_type: AlertType | None = None,
        ssid: str | None = None,
        bssid: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 500,
    ) -> list[Alert]:
        """Filtered alert history, newest first."""
        clauses: list[str] = []
        parameters: list[object] = []
        if status is not None:
            clauses.append("status = ?")
            parameters.append(status.value)
        if severity is not None:
            clauses.append("severity = ?")
            parameters.append(severity.value)
        if alert_type is not None:
            clauses.append("alert_type = ?")
            parameters.append(alert_type.value)
        if ssid is not None:
            clauses.append("ssid = ?")
            parameters.append(ssid)
        if bssid is not None:
            clauses.append("bssid = ?")
            parameters.append(bssid)
        if since is not None:
            clauses.append("created_at >= ?")
            parameters.append(_iso(since))
        if until is not None:
            clauses.append("created_at <= ?")
            parameters.append(_iso(until))

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""  # noqa: S608 - literal clauses
        rows = self._db.query(
            f"SELECT * FROM alerts {where} ORDER BY created_at DESC, id DESC LIMIT ?",  # noqa: S608
            (*parameters, max(1, int(limit))),
        )
        return [self._to_model(row) for row in rows]

    def counts_by_severity(self) -> dict[str, int]:
        """Open alert counts keyed by severity value."""
        rows = self._db.query(
            "SELECT severity, COUNT(*) AS n FROM alerts WHERE status = 'active' GROUP BY severity"
        )
        return {str(row["severity"]): int(row["n"]) for row in rows}

    def count(self, *, status: AlertStatus | None = None) -> int:
        """Count alerts, optionally filtered by status."""
        if status is None:
            row = self._db.query_one("SELECT COUNT(*) AS n FROM alerts")
        else:
            row = self._db.query_one(
                "SELECT COUNT(*) AS n FROM alerts WHERE status = ?", (status.value,)
            )
        return int(row["n"]) if row else 0

    def prune(self, older_than: datetime) -> int:
        """Delete resolved/acknowledged alerts older than ``older_than``."""
        cursor = self._db.execute(
            "DELETE FROM alerts WHERE status != 'active' AND created_at < ?",
            (_iso(older_than),),
        )
        return cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0

    @staticmethod
    def _to_model(row: Any) -> Alert:
        data = dict(row)
        data["reasons"] = json.loads(data.get("reasons") or "[]")
        return Alert.from_dict(data)


class SettingRepository:
    """Persistence for application settings."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def get(self, key: str, default: str | None = None) -> str | None:
        """Read a setting value."""
        row = self._db.query_one("SELECT value FROM application_settings WHERE key = ?", (key,))
        if row is None:
            return default
        value: str | None = row["value"]
        return value if value is not None else default

    def set(self, key: str, value: str | None, *, updated_at: datetime | None = None) -> ApplicationSetting:
        """Write a setting value and return the stored record."""
        setting = ApplicationSetting(key=key, value=value, updated_at=updated_at or utcnow())
        self._db.execute(
            "INSERT INTO application_settings (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (setting.key, setting.value, _iso(setting.updated_at)),
        )
        return setting

    def set_many(self, values: dict[str, str | None]) -> None:
        """Write several settings in one transaction."""
        with self._db.transaction() as connection:
            stamp = utcnow().isoformat()
            connection.executemany(
                "INSERT INTO application_settings (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                [(key, value, stamp) for key, value in values.items()],
            )

    def all(self) -> dict[str, str | None]:
        """Every stored setting as a key/value mapping."""
        rows = self._db.query("SELECT key, value FROM application_settings")
        return {str(row["key"]): (row["value"] if row["value"] is not None else None) for row in rows}

    def delete(self, key: str) -> bool:
        """Remove a setting; return whether anything was removed."""
        cursor = self._db.execute("DELETE FROM application_settings WHERE key = ?", (key,))
        return bool(cursor.rowcount)


class RiskScoreRepository:
    """Persistence for the risk score history shown in investigation views."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def add(
        self,
        *,
        ssid: str | None,
        bssid: str | None,
        score: int,
        severity: Severity | str,
        reasons: list[str] | tuple[str, ...],
        created_at: datetime | None = None,
    ) -> int:
        """Store one score evaluation and return its identifier."""
        severity_value = severity.value if isinstance(severity, Severity) else str(severity)
        cursor = self._db.execute(
            "INSERT INTO risk_scores (ssid, bssid, score, severity, reasons, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                ssid,
                bssid,
                int(score),
                severity_value,
                json.dumps(list(reasons)),
                _iso(created_at or utcnow()),
            ),
        )
        return int(cursor.lastrowid or 0)

    def history(
        self,
        *,
        ssid: str | None = None,
        bssid: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Score history for an identity, newest first."""
        clauses: list[str] = []
        parameters: list[object] = []
        if ssid is not None:
            clauses.append("ssid = ?")
            parameters.append(ssid)
        if bssid is not None:
            clauses.append("bssid = ?")
            parameters.append(bssid)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""  # noqa: S608 - literal clauses
        rows = self._db.query(
            f"SELECT * FROM risk_scores {where} ORDER BY created_at DESC, id DESC LIMIT ?",  # noqa: S608
            (*parameters, max(1, int(limit))),
        )
        history: list[dict[str, Any]] = []
        for row in rows:
            entry = dict(row)
            entry["reasons"] = json.loads(entry.get("reasons") or "[]")
            history.append(entry)
        return history

    def prune(self, older_than: datetime) -> int:
        """Delete score history older than ``older_than``."""
        cursor = self._db.execute("DELETE FROM risk_scores WHERE created_at < ?", (_iso(older_than),))
        return cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0
