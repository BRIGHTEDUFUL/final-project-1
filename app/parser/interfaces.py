"""Parser for ``netsh wlan show interfaces`` output.

Used for availability checks, connection context and the dashboard "current
environment" panel. Defensive like the network parser: unknown labels are
ignored, missing values stay ``None``.

Locale note: labels translate with Windows, value shapes do not. A block is
started on the GUID value even when the "Name" label is localised, connection
state falls back to "a BSSID is reported" (netsh lists one only while
connected), and MAC/percent/integer values are recovered by shape.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = ["InterfaceInfo", "parse_interfaces"]

_KEY_VALUE_PATTERN = re.compile(r"^\s*(?P<key>[^:]+?)\s*:\s*(?P<value>.*)$")
_NAME_KEY_PATTERN = re.compile(r"^name$", re.IGNORECASE)
_MAC_PATTERN = re.compile(r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")
_GUID_PATTERN = re.compile(
    r"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$"
)
_SIGNAL_PATTERN = re.compile(r"^(\d{1,3})\s*%$")


@dataclass(slots=True)
class InterfaceInfo:
    """Status of one wireless interface as reported by the OS."""

    name: str | None = None
    description: str | None = None
    mac_address: str | None = None
    state: str | None = None
    ssid: str | None = None
    bssid: str | None = None
    channel: int | None = None
    authentication: str | None = None
    signal: int | None = None
    rssi: int | None = None
    raw: dict[str, str] = field(default_factory=dict)

    @property
    def is_connected(self) -> bool:
        """``True`` when the interface reports an active connection.

        The ``State`` label translates with Windows; a reported BSSID does
        not — netsh lists one only while the interface is connected — so it
        doubles as locale-proof evidence.
        """
        if self.bssid:
            return True
        return bool(self.state) and self.state.strip().lower() == "connected"

    @property
    def is_up(self) -> bool:
        """``True`` when the interface is not disabled/absent."""
        if not self.state:
            return False
        return self.state.strip().lower() in {"connected", "disconnected"}


def _clean(value: str) -> str | None:
    text = value.strip()
    return text or None


def _to_int(value: str) -> int | None:
    text = value.strip()
    if re.fullmatch(r"-?\d{1,4}", text):
        return int(text)
    return None


def _to_signal(value: str) -> int | None:
    match = _SIGNAL_PATTERN.match(value.strip())
    if not match:
        return None
    return max(0, min(100, int(match.group(1))))


def parse_interfaces(text: str) -> list[InterfaceInfo]:
    """Parse raw interface text into :class:`InterfaceInfo` records."""
    if not text or not text.strip():
        return []

    interfaces: list[InterfaceInfo] = []
    current: InterfaceInfo | None = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue

        match = _KEY_VALUE_PATTERN.match(line)
        if not match:
            continue

        key = match.group("key").strip()
        value = match.group("value").strip()

        if _NAME_KEY_PATTERN.match(key):
            current = InterfaceInfo(name=_clean(value))
            interfaces.append(current)
            continue

        if current is None:
            # Localised Windows relabels "Name"; start the block on the GUID
            # value instead, whose shape never translates.
            if _GUID_PATTERN.match(value):
                current = InterfaceInfo()
                interfaces.append(current)
                current.raw[key] = value
            continue

        lower = key.lower()
        current.raw[key] = value

        if lower == "description":
            current.description = _clean(value)
        elif lower in {"physical address", "physical address (mac)", "mac address"}:
            if _MAC_PATTERN.match(value):
                current.mac_address = value.lower()
        elif lower == "state":
            current.state = _clean(value)
        elif lower == "ssid":
            current.ssid = _clean(value)
        elif lower in {"ap bssid", "bssid"}:
            if _MAC_PATTERN.match(value):
                current.bssid = value.lower()
        elif lower == "channel":
            current.channel = _to_int(value)
        elif lower == "authentication":
            current.authentication = _clean(value)
        elif lower == "signal":
            current.signal = _to_signal(value)
        elif lower in {"rssi", "radio signal"}:
            current.rssi = _to_int(value)
        else:
            # Locale-tolerant value shapes: labels translate, MAC addresses,
            # percentages and bare channel integers do not. The first MAC in
            # a block is the physical address; a second one is the BSSID
            # (netsh lists it only while connected).
            if _MAC_PATTERN.match(value):
                if current.mac_address is None:
                    current.mac_address = value.lower()
                elif current.bssid is None:
                    current.bssid = value.lower()
            else:
                if current.signal is None:
                    percent = _to_signal(value)
                    if percent is not None:
                        current.signal = percent
                if current.channel is None:
                    integer = _to_int(value)
                    if integer is not None and 1 <= integer <= 255:
                        current.channel = integer

    return interfaces
