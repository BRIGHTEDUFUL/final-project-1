"""Network observation — one sighting of a wireless network.

Scanner-agnostic: adapters parse raw operating-system scan output into this
model, detection rules consume it, storage persists it. Nothing here knows
about any particular scan command or the graphical toolkit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.models.base import (
    ModelValidationError,
    coerce_datetime,
    coerce_optional_int,
    coerce_optional_str,
    utcnow,
)
from app.models.bssid import InvalidBssidError, normalize_bssid
from app.models.security import SecurityMode, classify_security

__all__ = ["NetworkObservation"]

MIN_SIGNAL_STRENGTH = 0
MAX_SIGNAL_STRENGTH = 100
MIN_CHANNEL = 1
MAX_CHANNEL = 255


@dataclass(frozen=True, slots=True)
class NetworkObservation:
    """A single, immutable observation of a nearby wireless network.

    Parameters
    ----------
    id:
        Storage-assigned identifier, ``None`` before persistence.
    ssid:
        Broadcast network name; ``None`` for hidden or unnamed networks.
    bssid:
        Access point radio identifier in ``aa:bb:cc:dd:ee:ff`` form.
    signal_strength:
        Signal quality as reported by the OS, 0-100 (percent).
    security:
        Security label exactly as reported, for display and audit.
    channel:
        Radio channel where the platform reports one.
    observed_at:
        Observation time; naive input is treated as UTC.
    """

    id: int | None = None
    ssid: str | None = None
    bssid: str | None = None
    signal_strength: int | None = None
    security: str | None = None
    channel: int | None = None
    observed_at: datetime = field(default_factory=utcnow)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "ssid",
            coerce_optional_str(self.ssid, field_name="ssid", strip=False),
        )
        try:
            object.__setattr__(self, "bssid", normalize_bssid(self.bssid))
        except InvalidBssidError as exc:
            raise ModelValidationError(str(exc)) from exc

        if self.id is not None and (isinstance(self.id, bool) or not isinstance(self.id, int)):
            raise ModelValidationError(f"id must be an integer or None, got {self.id!r}")

        object.__setattr__(
            self,
            "signal_strength",
            coerce_optional_int(
                self.signal_strength,
                field_name="signal_strength",
                minimum=MIN_SIGNAL_STRENGTH,
                maximum=MAX_SIGNAL_STRENGTH,
            ),
        )
        object.__setattr__(
            self,
            "channel",
            coerce_optional_int(
                self.channel,
                field_name="channel",
                minimum=MIN_CHANNEL,
                maximum=MAX_CHANNEL,
            ),
        )
        object.__setattr__(
            self,
            "security",
            coerce_optional_str(self.security, field_name="security"),
        )
        object.__setattr__(self, "observed_at", coerce_datetime(self.observed_at, field_name="observed_at"))

        if self.ssid is None and self.bssid is None:
            raise ModelValidationError("an observation requires at least an SSID or a BSSID")

    @property
    def security_mode(self) -> SecurityMode | None:
        """Classified security; ``None`` when security was not reported."""
        return classify_security(self.security)

    @property
    def is_hidden(self) -> bool:
        """``True`` when the network does not broadcast a name."""
        return self.ssid is None

    @property
    def identity(self) -> str:
        """Stable display identity for listings and log messages."""
        if self.ssid and self.bssid:
            return f"{self.ssid} [{self.bssid}]"
        return self.ssid or self.bssid or "<unknown>"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "id": self.id,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "signal_strength": self.signal_strength,
            "security": self.security,
            "channel": self.channel,
            "observed_at": self.observed_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NetworkObservation:
        """Rebuild an observation from :meth:`to_dict` output."""
        if not isinstance(data, dict):
            raise ModelValidationError(f"expected a mapping, got {type(data).__name__}")
        return cls(
            id=data.get("id"),
            ssid=data.get("ssid"),
            bssid=data.get("bssid"),
            signal_strength=data.get("signal_strength"),
            security=data.get("security"),
            channel=data.get("channel"),
            observed_at=data.get("observed_at") or utcnow(),
        )
