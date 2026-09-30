"""Shared test helpers (not collected by pytest itself)."""

from __future__ import annotations

import threading

from app.scanner.raw import RawScanResult

__all__ = ["FakeScanner"]


class FakeScanner:
    """Duck-typed scanner returning canned text instead of running a scan."""

    def __init__(
        self,
        network_text: str = "",
        interface_text: str = "",
        *,
        usable: tuple[bool, str] = (True, "wireless interface available"),
        scan_ok: bool = True,
        delay: float = 0.0,
    ) -> None:
        self.network_text = network_text
        self.interface_text = interface_text
        self.usable = usable
        self.scan_ok = scan_ok
        self.delay = delay
        self.scan_calls = 0
        self.interface_calls = 0

    def available(self) -> tuple[bool, str]:
        return self.usable

    def scan(self) -> RawScanResult:
        self.scan_calls += 1
        if self.delay:
            threading.Event().wait(self.delay)
        return RawScanResult.create(
            ("netsh", "wlan", "show", "networks", "mode=bssid"),
            self.network_text,
            "" if self.scan_ok else "command failed",
            0 if self.scan_ok else 1,
            0.01,
        )

    def show_interfaces(self) -> RawScanResult:
        self.interface_calls += 1
        return RawScanResult.create(
            ("netsh", "wlan", "show", "interfaces"),
            self.interface_text,
            "",
            0,
            0.01,
        )
