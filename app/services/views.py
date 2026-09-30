"""Derived views over stored data (kept out of the GUI so tests can use them).

A *snapshot* is the current state of one identity: the latest observation, its
trust status and its most recent risk score, merged from separate tables.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.models import Alert, NetworkObservation, Severity, TrustedNetwork

__all__ = ["NetworkSnapshot", "build_snapshots"]


@dataclass(frozen=True, slots=True)
class NetworkSnapshot:
    """One row of the live-networks view."""

    ssid: str | None
    bssid: str | None
    signal_strength: int | None
    security: str | None
    channel: int | None
    observed_at: datetime | None
    trusted: bool
    approved_bssid: bool
    score: int | None
    severity: str | None

    @property
    def identity(self) -> tuple[str | None, str | None]:
        """Stable ``(ssid, bssid)`` key."""
        return (self.ssid, self.bssid)

    @property
    def trust_label(self) -> str:
        """Human-readable trust state."""
        if self.trusted and (self.approved_bssid or self.bssid is None):
            return "Trusted"
        if self.trusted:
            return "Trusted name, new radio"
        return "Unknown"

    @property
    def is_suspicious(self) -> bool:
        """``True`` when the identity carries a non-low score."""
        return self.severity is not None and self.severity != "low"


def build_snapshots(
    observations: list[NetworkObservation],
    trusted: list[TrustedNetwork],
    scores: list[dict] | None = None,
) -> list[NetworkSnapshot]:
    """Merge latest observations with trust profiles and score history.

    ``observations`` may contain many sightings per identity; only the most
    recent one is used. Rows are ordered by signal strength descending, with
    unsignalled entries last.
    """
    profiles = {profile.ssid: profile for profile in trusted}
    latest: dict[tuple[str | None, str | None], NetworkObservation] = {}
    for observation in observations:
        key = (observation.ssid, observation.bssid)
        current = latest.get(key)
        if current is None or observation.observed_at >= current.observed_at:
            latest[key] = observation

    score_map: dict[tuple[str | None, str | None], dict] = {}
    for entry in scores or []:
        score_map[(entry.get("ssid"), entry.get("bssid"))] = entry

    snapshots: list[NetworkSnapshot] = []
    for (ssid, bssid), observation in latest.items():
        profile = profiles.get(ssid) if ssid is not None else None
        score_entry = score_map.get((ssid, bssid))
        snapshots.append(
            NetworkSnapshot(
                ssid=ssid,
                bssid=bssid,
                signal_strength=observation.signal_strength,
                security=observation.security,
                channel=observation.channel,
                observed_at=observation.observed_at,
                trusted=profile is not None,
                approved_bssid=bool(profile and profile.approves(bssid)),
                score=int(score_entry["score"]) if score_entry else None,
                severity=str(score_entry["severity"]) if score_entry else None,
            )
        )

    snapshots.sort(
        key=lambda item: (
            item.signal_strength if item.signal_strength is not None else -1,
            item.ssid or "",
        ),
        reverse=True,
    )
    return snapshots


def alerts_by_identity(alerts: list[Alert]) -> dict[tuple[str | None, str | None], Alert]:
    """Index open alerts by identity, keeping the highest score seen."""
    indexed: dict[tuple[str | None, str | None], Alert] = {}
    for alert in alerts:
        key = (alert.ssid, alert.bssid)
        existing = indexed.get(key)
        if existing is None or alert.risk_score > existing.risk_score:
            indexed[key] = alert
    return indexed


def severity_name(severity: Severity | None) -> str | None:
    """Return the wire value of a severity, if present."""
    return severity.value if severity else None
