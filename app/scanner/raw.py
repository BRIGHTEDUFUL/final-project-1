"""Raw scan output — bytes of text captured from the operating system.

The scanner never interprets results: it only captures them. Parsing lives in
:mod:`app.parser`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.models.base import utcnow

__all__ = ["RawScanResult"]


@dataclass(frozen=True, slots=True)
class RawScanResult:
    """Outcome of one scan command invocation."""

    command: tuple[str, ...]
    stdout: str
    stderr: str
    returncode: int
    duration_seconds: float
    captured_at: datetime

    @classmethod
    def create(
        cls,
        command: tuple[str, ...],
        stdout: str,
        stderr: str,
        returncode: int,
        duration_seconds: float,
    ) -> RawScanResult:
        """Build a result stamped with the current UTC time."""
        return cls(
            command=command,
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
            duration_seconds=round(duration_seconds, 4),
            captured_at=utcnow(),
        )

    @property
    def ok(self) -> bool:
        """``True`` when the command exited successfully."""
        return self.returncode == 0

    @property
    def text(self) -> str:
        """Combined output, useful for diagnostics and availability checks."""
        return f"{self.stdout}\n{self.stderr}".strip()

    def summary(self) -> str:
        """Short human-readable outcome for logs."""
        if self.ok:
            return f"{self.command[0]} ok in {self.duration_seconds:.2f}s"
        return (
            f"{self.command[0]} failed with code {self.returncode}: "
            f"{(self.stderr or self.stdout).strip()[:200]}"
        )
