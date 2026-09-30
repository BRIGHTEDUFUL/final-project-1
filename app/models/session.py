"""Scan session — the lifecycle record of one monitoring run."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import Any

from app.models.base import ModelValidationError, coerce_datetime, coerce_optional_int, utcnow

__all__ = ["ScanSession", "ScanSessionStatus"]


class ScanSessionStatus(StrEnum):
    """Lifecycle state of a scan session."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ScanSession:
    """Metadata about a scan or monitoring run."""

    id: int | None = None
    started_at: datetime = field(default_factory=utcnow)
    completed_at: datetime | None = None
    network_count: int = 0
    status: ScanSessionStatus = ScanSessionStatus.RUNNING

    def __post_init__(self) -> None:
        if self.id is not None and (isinstance(self.id, bool) or not isinstance(self.id, int)):
            raise ModelValidationError(f"id must be an integer or None, got {self.id!r}")

        object.__setattr__(self, "started_at", coerce_datetime(self.started_at, field_name="started_at"))
        object.__setattr__(
            self,
            "completed_at",
            coerce_datetime(self.completed_at, field_name="completed_at", required=False),
        )
        object.__setattr__(
            self,
            "network_count",
            coerce_optional_int(self.network_count, field_name="network_count", minimum=0) or 0,
        )

        if not isinstance(self.status, ScanSessionStatus):
            try:
                object.__setattr__(self, "status", ScanSessionStatus(self.status))
            except (ValueError, TypeError) as exc:
                raise ModelValidationError(
                    f"status must be one of {[s.value for s in ScanSessionStatus]}, got {self.status!r}"
                ) from exc

        if self.completed_at is not None and self.completed_at < self.started_at:
            raise ModelValidationError("completed_at cannot be earlier than started_at")

    def is_finished(self) -> bool:
        """``True`` when the session reached a terminal state."""
        return self.status is not ScanSessionStatus.RUNNING

    def finish(
        self,
        status: ScanSessionStatus = ScanSessionStatus.COMPLETED,
        *,
        network_count: int | None = None,
        completed_at: datetime | None = None,
    ) -> ScanSession:
        """Return a terminal copy of this session."""
        if status is ScanSessionStatus.RUNNING:
            raise ModelValidationError("finish() requires a terminal status")
        return replace(
            self,
            status=status,
            completed_at=coerce_datetime(completed_at, field_name="completed_at", required=False)
            or self.completed_at
            or utcnow(),
            network_count=self.network_count if network_count is None else network_count,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "id": self.id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "network_count": self.network_count,
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanSession:
        """Rebuild a session from :meth:`to_dict` output."""
        if not isinstance(data, dict):
            raise ModelValidationError(f"expected a mapping, got {type(data).__name__}")
        return cls(
            id=data.get("id"),
            started_at=data.get("started_at") or utcnow(),
            completed_at=data.get("completed_at"),
            network_count=data.get("network_count") or 0,
            status=data.get("status") or ScanSessionStatus.RUNNING,
        )
