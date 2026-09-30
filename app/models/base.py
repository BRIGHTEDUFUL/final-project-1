"""Shared helpers for domain models: validation errors and time handling.

These helpers keep the models free of GUI and scanner dependencies while
making missing and malformed input explicit instead of silent.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

__all__ = [
    "ModelValidationError",
    "coerce_datetime",
    "coerce_optional_int",
    "coerce_optional_str",
    "coerce_str",
    "utcnow",
]


class ModelValidationError(ValueError):
    """Raised when a domain model receives an invalid value."""


def utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def coerce_datetime(
    value: datetime | str | None,
    *,
    field_name: str = "timestamp",
    required: bool = True,
) -> datetime | None:
    """Coerce a datetime or ISO-8601 string to an aware UTC datetime.

    Naive values are interpreted as UTC. ``None`` is returned when the value is
    optional, otherwise :class:`ModelValidationError` is raised.
    """
    if value is None:
        if required:
            raise ModelValidationError(f"{field_name} is required")
        return None

    if isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            value = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ModelValidationError(f"{field_name} is not a valid ISO-8601 datetime: {value!r}") from exc

    if not isinstance(value, datetime):
        raise ModelValidationError(f"{field_name} must be a datetime or ISO-8601 string, got {value!r}")

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def coerce_optional_str(value: Any, *, field_name: str, strip: bool = True) -> str | None:
    """Return a clean string, mapping ``None`` and empty input to ``None``."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ModelValidationError(f"{field_name} must be a string or None, got {value!r}")
    cleaned = value.strip() if strip else value
    return cleaned or None


def coerce_str(value: Any, *, field_name: str, strip: bool = True) -> str:
    """Return a non-empty string or raise :class:`ModelValidationError`."""
    cleaned = coerce_optional_str(value, field_name=field_name, strip=strip)
    if cleaned is None:
        raise ModelValidationError(f"{field_name} is required")
    return cleaned


def coerce_optional_int(
    value: Any,
    *,
    field_name: str,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int | None:
    """Return a bounded integer, mapping ``None``/empty to ``None``."""
    if value is None or value == "":
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelValidationError(f"{field_name} must be an integer or None, got {value!r}")
    if minimum is not None and value < minimum:
        raise ModelValidationError(f"{field_name} must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise ModelValidationError(f"{field_name} must be <= {maximum}, got {value}")
    return value
