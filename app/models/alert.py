"""Alert — a persisted, explainable security event."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from app.models.base import (
    ModelValidationError,
    coerce_datetime,
    coerce_optional_int,
    coerce_optional_str,
    utcnow,
)
from app.models.bssid import normalize_bssid

__all__ = ["Alert", "AlertStatus", "AlertType", "Severity"]

DEFAULT_THRESHOLDS = (30, 60, 80)


class Severity(StrEnum):
    """Risk classification bands (baseline thresholds, see documentation §10)."""

    LOW = "low"
    SUSPICIOUS = "suspicious"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Ordered rank for sorting: low < suspicious < high < critical."""
        return {Severity.LOW: 0, Severity.SUSPICIOUS: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}[self]

    @classmethod
    def from_score(
        cls,
        score: int,
        thresholds: tuple[int, int, int] = DEFAULT_THRESHOLDS,
    ) -> Severity:
        """Map a 0-100 risk score to a severity band.

        Scores are clamped into 0-100 and thresholds are validated ascending;
        an out-of-range score can therefore never produce an unknown band.
        """
        if len(thresholds) != 3 or not all(isinstance(t, int) for t in thresholds):
            raise ModelValidationError(f"thresholds must be three integers, got {thresholds!r}")
        suspicious, high, critical = thresholds
        if not (0 < suspicious < high < critical <= 100):
            raise ModelValidationError(f"thresholds must satisfy 0 < s < h < c <= 100, got {thresholds!r}")

        if not isinstance(score, int) or isinstance(score, bool):
            raise ModelValidationError(f"score must be an integer, got {score!r}")
        bounded = max(0, min(100, score))
        if bounded >= critical:
            return cls.CRITICAL
        if bounded >= high:
            return cls.HIGH
        if bounded >= suspicious:
            return cls.SUSPICIOUS
        return cls.LOW


class AlertStatus(StrEnum):
    """Workflow state of an alert."""

    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class AlertType(StrEnum):
    """Detection indicator that produced the alert."""

    DUPLICATE_SSID = "duplicate_ssid"
    UNKNOWN_BSSID = "unknown_bssid"
    SECURITY_DOWNGRADE = "security_downgrade"
    NEW_ACCESS_POINT = "new_access_point"
    SUSPICIOUS_SIGNAL = "suspicious_signal"
    PERSISTENCE = "persistence"
    OTHER = "other"


def _coerce_reasons(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = [value]
    if isinstance(value, (bytes, bytearray)) or not hasattr(value, "__iter__"):
        raise ModelValidationError(f"reasons must be a sequence of strings, got {value!r}")

    reasons: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ModelValidationError(f"every reason must be a string, got {item!r}")
        text = item.strip()
        if text:
            reasons.append(text)
    return tuple(reasons)


@dataclass(frozen=True, slots=True)
class Alert:
    """An explainable security event stored for review and follow-up."""

    id: int | None = None
    ssid: str | None = None
    bssid: str | None = None
    alert_type: AlertType = AlertType.OTHER
    risk_score: int = 0
    severity: Severity | None = None
    reasons: tuple[str, ...] = ()
    created_at: datetime = field(default_factory=utcnow)
    status: AlertStatus = AlertStatus.ACTIVE

    def __post_init__(self) -> None:
        if self.id is not None and (isinstance(self.id, bool) or not isinstance(self.id, int)):
            raise ModelValidationError(f"id must be an integer or None, got {self.id!r}")

        object.__setattr__(self, "ssid", coerce_optional_str(self.ssid, field_name="ssid", strip=False))
        object.__setattr__(self, "bssid", normalize_bssid(self.bssid))

        if self.ssid is None and self.bssid is None:
            raise ModelValidationError("an alert requires at least an SSID or a BSSID")

        if not isinstance(self.alert_type, AlertType):
            try:
                object.__setattr__(self, "alert_type", AlertType(self.alert_type))
            except (ValueError, TypeError) as exc:
                raise ModelValidationError(
                    f"alert_type must be one of {[t.value for t in AlertType]}, got {self.alert_type!r}"
                ) from exc

        score = coerce_optional_int(self.risk_score, field_name="risk_score", minimum=0, maximum=100)
        object.__setattr__(self, "risk_score", 0 if score is None else score)

        if self.severity is None:
            object.__setattr__(self, "severity", Severity.from_score(self.risk_score))
        elif not isinstance(self.severity, Severity):
            try:
                object.__setattr__(self, "severity", Severity(self.severity))
            except (ValueError, TypeError) as exc:
                raise ModelValidationError(
                    f"severity must be one of {[s.value for s in Severity]}, got {self.severity!r}"
                ) from exc

        object.__setattr__(self, "reasons", _coerce_reasons(self.reasons))
        object.__setattr__(self, "created_at", coerce_datetime(self.created_at, field_name="created_at"))

        if not isinstance(self.status, AlertStatus):
            try:
                object.__setattr__(self, "status", AlertStatus(self.status))
            except (ValueError, TypeError) as exc:
                raise ModelValidationError(
                    f"status must be one of {[s.value for s in AlertStatus]}, got {self.status!r}"
                ) from exc

    @classmethod
    def from_score(
        cls,
        *,
        ssid: str | None,
        bssid: str | None,
        alert_type: AlertType | str,
        risk_score: int,
        reasons: tuple[str, ...] | list[str] | str,
        thresholds: tuple[int, int, int] = DEFAULT_THRESHOLDS,
        created_at: datetime | None = None,
        status: AlertStatus = AlertStatus.ACTIVE,
        id: int | None = None,
    ) -> Alert:
        """Create an alert, deriving its severity from the score."""
        return cls(
            id=id,
            ssid=ssid,
            bssid=bssid,
            alert_type=alert_type,  # type: ignore[arg-type]
            risk_score=risk_score,
            severity=Severity.from_score(risk_score, thresholds),
            reasons=_coerce_reasons(reasons),
            created_at=created_at or utcnow(),
            status=status,
        )

    @property
    def evidence(self) -> str:
        """Human-readable explanation of why the alert fired."""
        return "; ".join(self.reasons) if self.reasons else "no specific evidence recorded"

    @property
    def is_open(self) -> bool:
        """``True`` while the alert still needs operator attention."""
        return self.status is AlertStatus.ACTIVE

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "id": self.id,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "alert_type": self.alert_type.value,
            "risk_score": self.risk_score,
            "severity": self.severity.value if self.severity else None,
            "reasons": list(self.reasons),
            "created_at": self.created_at.isoformat(),
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Alert:
        """Rebuild an alert from :meth:`to_dict` output."""
        if not isinstance(data, dict):
            raise ModelValidationError(f"expected a mapping, got {type(data).__name__}")
        return cls(
            id=data.get("id"),
            ssid=data.get("ssid"),
            bssid=data.get("bssid"),
            alert_type=data.get("alert_type") or AlertType.OTHER,
            risk_score=data.get("risk_score") or 0,
            severity=data.get("severity"),
            reasons=tuple(data.get("reasons") or ()),
            created_at=data.get("created_at") or utcnow(),
            status=data.get("status") or AlertStatus.ACTIVE,
        )
