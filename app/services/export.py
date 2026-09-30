"""CSV export for local records.

Files are written UTF-8 with a BOM so spreadsheet software opens international
characters correctly, and via a temporary file so a failed export never leaves
a half-written file behind.
"""

from __future__ import annotations

import csv
import logging
from collections.abc import Iterable, Sequence
from pathlib import Path

from app.models import Alert, NetworkObservation

logger = logging.getLogger(__name__)

__all__ = ["export_alerts_csv", "export_observations_csv"]

ALERT_COLUMNS: tuple[str, ...] = (
    "id",
    "created_at",
    "first_seen",
    "last_seen",
    "status",
    "severity",
    "risk_score",
    "alert_type",
    "ssid",
    "bssid",
    "occurrence_count",
    "reasons",
)

OBSERVATION_COLUMNS: tuple[str, ...] = (
    "id",
    "observed_at",
    "ssid",
    "bssid",
    "signal_strength",
    "security",
    "channel",
)


class ExportError(Exception):
    """Raised when records cannot be written to CSV."""


def _write_csv(path: Path, columns: Sequence[str], rows: Iterable[dict[str, object]]) -> Path:
    path = Path(path)
    if path.exists() and not path.is_file():
        raise ExportError(f"{path} is not a file")

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    written = 0
    try:
        with temporary.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(columns), extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
                written += 1
        temporary.replace(path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise ExportError(f"cannot write {path}: {exc}") from exc

    logger.info("exported %d rows to %s", written, path)
    return path


def _alert_row(alert: Alert) -> dict[str, object]:
    return {
        "id": alert.id,
        "created_at": alert.created_at.isoformat(),
        "first_seen": alert.first_seen.isoformat() if alert.first_seen else "",
        "last_seen": alert.last_seen.isoformat() if alert.last_seen else "",
        "status": alert.status.value,
        "severity": alert.severity.value if alert.severity else "",
        "risk_score": alert.risk_score,
        "alert_type": alert.alert_type.value,
        "ssid": alert.ssid or "",
        "bssid": alert.bssid or "",
        "occurrence_count": alert.occurrence_count,
        "reasons": " | ".join(alert.reasons),
    }


def _observation_row(observation: NetworkObservation) -> dict[str, object]:
    return {
        "id": observation.id,
        "observed_at": observation.observed_at.isoformat(),
        "ssid": observation.ssid or "",
        "bssid": observation.bssid or "",
        "signal_strength": observation.signal_strength
        if observation.signal_strength is not None
        else "",
        "security": observation.security or "",
        "channel": observation.channel if observation.channel is not None else "",
    }


def export_alerts_csv(path: Path | str, alerts: Iterable[Alert]) -> Path:
    """Write alerts to ``path`` and return the file location."""
    return _write_csv(Path(path), ALERT_COLUMNS, (_alert_row(a) for a in alerts))


def export_observations_csv(path: Path | str, observations: Iterable[NetworkObservation]) -> Path:
    """Write observations to ``path`` and return the file location."""
    return _write_csv(Path(path), OBSERVATION_COLUMNS, (_observation_row(o) for o in observations))
