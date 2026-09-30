"""Application setting — a single key/value preference persisted locally."""

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

__all__ = ["ApplicationSetting"]


@dataclass(frozen=True, slots=True)
class ApplicationSetting:
    """A string key/value pair; non-string values must be serialised by callers."""

    key: str = ""
    value: str | None = None
    updated_at: datetime = field(default_factory=utcnow)

    def __post_init__(self) -> None:
        object.__setattr__(self, "key", coerce_str(self.key, field_name="key"))
        object.__setattr__(self, "value", coerce_optional_str(self.value, field_name="value", strip=False))
        object.__setattr__(self, "updated_at", coerce_datetime(self.updated_at, field_name="updated_at"))

    @property
    def is_empty(self) -> bool:
        """``True`` when the setting carries no value."""
        return self.value is None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {"key": self.key, "value": self.value, "updated_at": self.updated_at.isoformat()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ApplicationSetting:
        """Rebuild a setting from :meth:`to_dict` output."""
        if not isinstance(data, dict):
            raise ModelValidationError(f"expected a mapping, got {type(data).__name__}")
        return cls(
            key=data.get("key") or "",
            value=data.get("value"),
            updated_at=data.get("updated_at") or utcnow(),
        )
