"""Scanner adapters that read wireless information from the operating system.

Adapters only collect raw output (:class:`RawScanResult`); parsing and
interpretation live in :mod:`app.parser`. Nothing here modifies network
settings or connects to a network.
"""

from __future__ import annotations

from app.scanner.errors import ScannerError, ScannerTimeoutError, ScannerUnavailableError
from app.scanner.netsh import (
    INTERFACE_COUNT_PATTERN,
    INTERFACES_COMMAND,
    NETWORKS_COMMAND,
    NetshScanner,
)
from app.scanner.raw import RawScanResult

__all__ = [
    "INTERFACES_COMMAND",
    "NETWORKS_COMMAND",
    "INTERFACE_COUNT_PATTERN",
    "NetshScanner",
    "RawScanResult",
    "ScannerError",
    "ScannerTimeoutError",
    "ScannerUnavailableError",
]
