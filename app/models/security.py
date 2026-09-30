"""Security label classification.

Observed and expected security are stored exactly as reported (for display and
audit) and classified on demand into an ordered mode so that detection rules
can reason about downgrades without string matching.
"""

from __future__ import annotations

from enum import StrEnum

from app.models.base import ModelValidationError, coerce_optional_str

__all__ = ["SecurityMode", "classify_security", "is_enterprise_security"]


class SecurityMode(StrEnum):
    """Coarse security classification ordered by relative strength."""

    OPEN = "open"
    WEP = "wep"
    WPA = "wpa"
    WPA2 = "wpa2"
    WPA3 = "wpa3"
    UNKNOWN = "unknown"

    @property
    def strength(self) -> int | None:
        """Relative strength: higher is stronger, ``None`` when unknown."""
        if self is SecurityMode.UNKNOWN:
            return None
        order = {
            SecurityMode.OPEN: 0,
            SecurityMode.WEP: 1,
            SecurityMode.WPA: 2,
            SecurityMode.WPA2: 3,
            SecurityMode.WPA3: 4,
        }
        return order[self]

    def is_weaker_than(self, other: SecurityMode) -> bool:
        """Return ``True`` when this mode is provably weaker than ``other``."""
        own = self.strength
        theirs = other.strength
        if own is None or theirs is None:
            return False
        return own < theirs


def classify_security(raw: object) -> SecurityMode | None:
    """Classify a reported security string.

    ``None`` and empty input mean "not reported" and return ``None``; an
    unrecognised but present value returns :attr:`SecurityMode.UNKNOWN`.
    """
    label = coerce_optional_str(raw, field_name="security")
    if label is None:
        return None

    text = label.lower()

    if "wpa3" in text or "sae" in text:
        return SecurityMode.WPA3
    if "wpa2" in text or "rsn" in text:
        return SecurityMode.WPA2
    if "wpa" in text:
        return SecurityMode.WPA
    if "wep" in text:
        return SecurityMode.WEP
    if any(token in text for token in ("open", "none", "not configured")):
        return SecurityMode.OPEN
    return SecurityMode.UNKNOWN


def is_enterprise_security(raw: object) -> bool:
    """Return ``True`` when the label describes an 802.1X/enterprise network."""
    label = coerce_optional_str(raw, field_name="security")
    if label is None:
        return False
    text = label.lower()
    return any(token in text for token in ("802.1x", "enterprise", "radius", "wpa2-enterprise"))


def require_security_mode(value: object, *, field_name: str) -> SecurityMode:
    """Coerce a value into a :class:`SecurityMode`, rejecting ``None``."""
    mode = classify_security(value)
    if mode is None:
        raise ModelValidationError(f"{field_name} is required")
    return mode
