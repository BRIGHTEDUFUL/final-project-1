"""Finding primitives: what a detection rule observed and why.

A finding never claims malice — it records an observable pattern plus
evidence an operator can verify.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from app.models import NetworkObservation, TrustedNetwork, utcnow

__all__ = ["DetectionContext", "Finding", "FindingRule", "IdentityKey", "group_findings"]


class FindingRule(StrEnum):
    """Detection indicator that produced a finding."""

    DUPLICATE_SSID = "duplicate_ssid"
    UNKNOWN_BSSID = "unknown_bssid"
    SECURITY_DOWNGRADE = "security_downgrade"
    NEW_ACCESS_POINT = "new_access_point"
    SUSPICIOUS_SIGNAL = "suspicious_signal"
    PERSISTENCE = "persistence"


IdentityKey = tuple[str | None, str | None]


@dataclass(frozen=True, slots=True)
class Finding:
    """One rule's observation about one identity, with evidence."""

    rule: FindingRule
    ssid: str | None
    bssid: str | None
    weight: int
    explanation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    occurred_at: datetime = field(default_factory=utcnow)

    @property
    def identity(self) -> IdentityKey:
        """Stable ``(ssid, bssid)`` key used for grouping."""
        return (self.ssid, self.bssid)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe representation, useful for alert evidence storage."""
        return {
            "rule": self.rule.value,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "weight": self.weight,
            "explanation": self.explanation,
            "evidence": dict(self.evidence),
            "occurred_at": self.occurred_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class DetectionContext:
    """Everything the rules need for one evaluation pass.

    Attributes
    ----------
    observations:
        Networks seen in the current scan.
    trusted:
        Approved baselines.
    known_bssids:
        BSSIDs observed in earlier scans (used by the new-access-point rule).
    connected_bssid / connected_signal:
        State of the adapter's own connection, used for signal comparison.
    history_available:
        ``False`` on the very first scan, which suppresses "new access point"
        findings that would otherwise flag the entire environment.
    """

    observations: tuple[NetworkObservation, ...] = ()
    trusted: tuple[TrustedNetwork, ...] = ()
    known_bssids: frozenset[str] = frozenset()
    connected_bssid: str | None = None
    connected_signal: int | None = None
    history_available: bool = True

    def trusted_for(self, ssid: str | None) -> TrustedNetwork | None:
        """Return the trusted profile matching ``ssid``, if any."""
        if ssid is None:
            return None
        for profile in self.trusted:
            if profile.ssid == ssid:
                return profile
        return None

    def is_approved(self, observation: NetworkObservation) -> bool:
        """``True`` when the observation matches a trusted profile fully."""
        profile = self.trusted_for(observation.ssid)
        if profile is None:
            return False
        if not profile.knows_bssids:
            return False
        return profile.approves(observation.bssid)


def group_findings(findings: list[Finding]) -> dict[IdentityKey, list[Finding]]:
    """Group findings by identity, preserving insertion order per group."""
    grouped: dict[IdentityKey, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.identity, []).append(finding)
    return grouped
