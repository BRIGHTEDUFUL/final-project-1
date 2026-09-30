"""Trusted network — the approved baseline used by detection rules.

One SSID may legitimately broadcast from several radios (mesh and enterprise
deployments), so a trusted profile stores a set of approved BSSIDs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.models.base import (
    ModelValidationError,
    coerce_datetime,
    coerce_optional_str,
    coerce_str,
    utcnow,
)
from app.models.bssid import normalize_bssid_list
from app.models.security import SecurityMode, classify_security

__all__ = ["TrustedNetwork"]


@dataclass(frozen=True, slots=True)
class TrustedNetwork:
    """An explicitly approved network profile.

    Parameters
    ----------
    ssid:
        Approved network name (required, cannot be blank).
    approved_bssids:
        Approved radio identifiers for this name; may be empty when only the
        name is known.
    expected_security:
        Security label the profile expects; ``None`` means "not specified",
        which disables downgrade detection for this profile.
    notes:
        Free-form operator notes.
    """

    id: int | None = None
    ssid: str = ""
    approved_bssids: tuple[str, ...] = ()
    expected_security: str | None = None
    created_at: datetime = field(default_factory=utcnow)
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ssid", coerce_str(self.ssid, field_name="ssid"))
        object.__setattr__(
            self,
            "approved_bssids",
            normalize_bssid_list(self.approved_bssids, field_name="approved_bssids"),
        )
        object.__setattr__(
            self,
            "expected_security",
            coerce_optional_str(self.expected_security, field_name="expected_security"),
        )
        object.__setattr__(self, "notes", coerce_optional_str(self.notes, field_name="notes") or "")
        object.__setattr__(self, "created_at", coerce_datetime(self.created_at, field_name="created_at"))

        if self.id is not None and (isinstance(self.id, bool) or not isinstance(self.id, int)):
            raise ModelValidationError(f"id must be an integer or None, got {self.id!r}")

    @property
    def expected_security_mode(self) -> SecurityMode | None:
        """Classified expected security; ``None`` when not specified."""
        return classify_security(self.expected_security)

    @property
    def knows_bssids(self) -> bool:
        """``True`` when at least one approved BSSID is registered."""
        return bool(self.approved_bssids)

    def approves(self, bssid: str | None) -> bool:
        """Return ``True`` when ``bssid`` is registered as approved."""
        if bssid is None or not self.approved_bssids:
            return False
        normalised = normalize_bssid_list([bssid])
        return bool(normalised) and normalised[0] in self.approved_bssids

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "id": self.id,
            "ssid": self.ssid,
            "approved_bssids": list(self.approved_bssids),
            "expected_security": self.expected_security,
            "created_at": self.created_at.isoformat(),
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrustedNetwork:
        """Rebuild a profile from :meth:`to_dict` output."""
        if not isinstance(data, dict):
            raise ModelValidationError(f"expected a mapping, got {type(data).__name__}")
        return cls(
            id=data.get("id"),
            ssid=data.get("ssid") or "",
            approved_bssids=tuple(data.get("approved_bssids") or ()),
            expected_security=data.get("expected_security"),
            created_at=data.get("created_at") or utcnow(),
            notes=data.get("notes") or "",
        )
