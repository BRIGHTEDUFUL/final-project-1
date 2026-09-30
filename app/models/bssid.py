"""BSSID normalisation.

Scan output frequently reports MAC addresses in different styles
(``AA-BB-CC-DD-EE-FF``, ``aa:bb:cc:dd:ee:ff``, ``aabb.ccdd.eeff`` or a bare
hex string). Detection logic must compare them consistently, so every model
stores the canonical lowercase colon-separated form.

Missing values become ``None``; malformed values raise
:class:`InvalidBssidError` so corrupted input never reaches detection rules
silently.
"""

from __future__ import annotations

import re

from app.models.base import ModelValidationError

__all__ = ["InvalidBssidError", "normalize_bssid", "normalize_bssid_list"]

_SEPARATOR_PATTERN = re.compile(r"[:\-\s]")
_HEX_PATTERN = re.compile(r"^[0-9a-f]{12}$")
_ZERO_BSSID = "00:00:00:00:00:00"


class InvalidBssidError(ModelValidationError):
    """Raised when a value cannot be interpreted as a BSSID."""


def normalize_bssid(value: object) -> str | None:
    """Normalise a BSSID to ``aa:bb:cc:dd:ee:ff``.

    ``None``, empty and whitespace-only input return ``None``. The all-zero
    placeholder is treated as "not reported" and also returns ``None``.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidBssidError(f"BSSID must be a string or None, got {value!r}")

    cleaned = value.strip()
    if not cleaned:
        return None

    if "." in cleaned and ":" not in cleaned and "-" not in cleaned:
        candidate = cleaned.replace(".", "")
    else:
        candidate = _SEPARATOR_PATTERN.sub("", cleaned)

    candidate = candidate.lower()
    if not _HEX_PATTERN.fullmatch(candidate):
        raise InvalidBssidError(f"invalid BSSID: {value!r}")

    octets = [candidate[index : index + 2] for index in range(0, 12, 2)]
    normalised = ":".join(octets)
    return None if normalised == _ZERO_BSSID else normalised


def normalize_bssid_list(values: object, *, field_name: str = "bssid list") -> tuple[str, ...]:
    """Normalise a sequence of BSSIDs, dropping duplicates, keeping order."""
    if values is None:
        return ()
    if isinstance(values, (str, bytes)):
        raise ModelValidationError(f"{field_name} must be a sequence of BSSIDs, got a single value")

    try:
        iterator = iter(values)
    except TypeError as exc:
        raise ModelValidationError(f"{field_name} must be iterable, got {values!r}") from exc

    seen: set[str] = set()
    result: list[str] = []
    for item in iterator:
        normalised = normalize_bssid(item)
        if normalised is None or normalised in seen:
            continue
        seen.add(normalised)
        result.append(normalised)
    return tuple(result)
