"""Scanner errors: every failure mode is explicit, never silent."""

from __future__ import annotations

__all__ = ["ScannerError", "ScannerTimeoutError", "ScannerUnavailableError"]


class ScannerError(Exception):
    """Base class for wireless scanning failures."""


class ScannerUnavailableError(ScannerError):
    """The WLAN facility cannot be used (missing command, service or adapter)."""


class ScannerTimeoutError(ScannerError):
    """The scan command did not finish within the allotted time."""
