"""Shared test helpers (not collected by pytest itself)."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable

from app.scanner.raw import RawScanResult

__all__ = [
    "FakeFrameSource",
    "FakeScanner",
    "MICROSOFT_OUI",
    "WFA_OUI",
    "build_beacon",
    "rsn_ie",
    "vendor_ie",
]

MICROSOFT_OUI = b"\x00\x50\xf2"
WFA_OUI = b"\x50\x6f\x9a"


def _mac(value: str) -> bytes:
    return bytes(int(part, 16) for part in value.split(":"))


def _ie(tag: int, value: bytes) -> bytes:
    return bytes((tag, len(value))) + value


def rsn_ie(
    *,
    akm: tuple[int, ...] = (2,),
    pairwise: tuple[int, ...] = (4,),
    group: int = 4,
    caps: int = 0,
) -> bytes:
    """Build an RSN (WPA2/WPA3) information element.

    ``caps`` is the raw RSN capabilities field (0x0040 = 802.11w capable,
    0x0080 = 802.11w required).
    """
    value = b"\x01\x00"  # version 1
    value += b"\x00\x0f\xac" + bytes((group,))  # group cipher suite
    value += bytes((len(pairwise),))
    value += b"".join(b"\x00\x0f\xac" + bytes((code,)) for code in pairwise)
    value += bytes((len(akm),))
    value += b"".join(b"\x00\x0f\xac" + bytes((code,)) for code in akm)
    value += caps.to_bytes(2, "little")
    return _ie(48, value)


def vendor_ie(oui: bytes, ie_type: int, tail: bytes = b"") -> bytes:
    """Build a vendor-specific information element (tag 221)."""
    return _ie(221, oui + bytes((ie_type,)) + tail)


def build_beacon(
    *,
    subtype: int = 8,
    frame_type: int = 0,
    bssid: str = "aa:bb:cc:dd:ee:ff",
    ssid: bytes | None = b"LabNet",
    channel: int | None = 6,
    capability: int = 0x0001,
    interval: int = 100,
    ies: Iterable[bytes] = (),
    radiotap: bool = False,
    order: bool = False,
) -> bytes:
    """Build a synthetic802.11 frame (beacon by default) for parser tests."""
    frame_control = bytes(((subtype << 4) | (frame_type << 2), 0x80 if order else 0x00))
    header = frame_control
    header += b"\x00\x00"  # duration
    header += _mac("ff:ff:ff:ff:ff:ff")  # address 1
    header += _mac(bssid)  # address 2
    header += _mac(bssid)  # address 3
    header += b"\x00\x00"  # sequence control
    if order:
        header += b"\x00\x00\x00\x00"  # HT Control field

    fixed = (0).to_bytes(8, "little")
    fixed += interval.to_bytes(2, "little")
    fixed += capability.to_bytes(2, "little")

    tags = b""
    if ssid is not None:
        tags += _ie(0, ssid)
    if channel is not None:
        tags += _ie(3, bytes((channel,)))
    for extra in ies:
        tags += extra

    frame = header + fixed + tags
    if radiotap:
        # version 0, pad 0, header length 8, no present fields
        return b"\x00\x00\x08\x00\x00\x00\x00\x00" + frame
    return frame


class FakeFrameSource:
    """Duck-typed frame source that records start/stop instead of capturing."""

    def __init__(self, *, start_error: Exception | None = None, datalink: int | None = 127) -> None:
        self.start_error = start_error
        self.datalink = datalink
        self.started = False
        self.stopped = False
        self.start_calls = 0
        self.stop_calls = 0
        self.callback: Callable[[bytes], None] | None = None
        self.on_error: Callable[[str], None] | None = None
        self.interface: str | None = None

    def start(
        self,
        on_frame: Callable[[bytes], None],
        *,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        if self.start_error is not None:
            raise self.start_error
        self.start_calls += 1
        self.started = True
        self.stopped = False
        self.callback = on_frame
        self.on_error = on_error

    def stop(self, timeout: float = 5.0) -> None:
        self.stop_calls += 1
        self.stopped = True
        self.callback = None
        self.on_error = None

    def feed(self, raw: bytes) -> None:
        """Deliver a captured frame the way the capture thread would."""
        assert self.callback is not None, "frame source was never started"
        self.callback(raw)


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
