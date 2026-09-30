"""Pure parsing of captured 802.11 beacon and probe-response frames.

The parser works on raw link-layer bytes (radiotap/PPI wrapped or bare
802.11) so it can be exercised entirely from fixtures: no capture library
is imported here. Only what access points broadcast in the clear is read
(SSID, channel, capability bits, information elements). Data frames, client
addresses and encrypted payloads are never interpreted -- passively observed
management frames only, mirroring the guarantees of the netsh scan path.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["BeaconInfo", "RsnInfo", "parse_frame"]

_MGMT_TYPE = 0
_BEACON_SUBTYPE = 8
_PROBE_RESPONSE_SUBTYPE = 5
_MGMT_SUBTYPES = (_BEACON_SUBTYPE, _PROBE_RESPONSE_SUBTYPE)

_MANAGEMENT_HEADER = 24  # frame control + duration + addr1..addr3 + sequence
_FRAME_CONTROL_ORDER = 0x80  # Order bit: a 4-byte HT Control field follows
_FIXED_PARAMETERS = 12  # timestamp (8) + beacon interval (2) + capability (2)

_IE_SSID = 0
_IE_DS_PARAMETER = 3
_IE_RSN = 48
_IE_VENDOR = 221

_MICROSOFT_OUI = b"\x00\x50\xf2"
_WFA_OUI = b"\x50\x6f\x9a"
_WPA1_IE_TYPE = 1
_WPS_IE_TYPE = 4

_PRIVACY_CAPABILITY = 0x0010
_RSN_CAPABILITY_MFPC = 0x0040  # 802.11w management frame protection capable
_RSN_CAPABILITY_MFPR = 0x0080  # 802.11w management frame protection required

# RSN AKM suite type selectors (IEEE 802.11 Table 9-151).
_AKM_PSK = frozenset({2, 6})  # PSK, PSK-SHA256
_AKM_SAE = frozenset({8, 9})  # SAE, FT-SAE -- the WPA3 authentication modes


@dataclass(frozen=True, slots=True)
class RsnInfo:
    """Parsed RSN (WPA2/WPA3) information element."""

    akm_types: tuple[int, ...]
    pairwise_types: tuple[int, ...]
    group_type: int | None
    mfpc: bool
    mfpr: bool

    @property
    def uses_psk(self) -> bool:
        """``True`` when a pre-shared-key AKM is advertised."""
        return bool(set(self.akm_types) & _AKM_PSK)

    @property
    def uses_sae(self) -> bool:
        """``True`` when SAE (WPA3) authentication is advertised."""
        return bool(set(self.akm_types) & _AKM_SAE)


@dataclass(frozen=True, slots=True)
class BeaconInfo:
    """One broadcast management frame from an access point."""

    bssid: str
    frame_kind: str  # "beacon" or "probe_response"
    ssid: str | None
    hidden: bool
    channel: int | None
    beacon_interval: int | None  # in time units (1 TU = 1024 microseconds)
    privacy: bool
    rsn: RsnInfo | None
    wpa1: bool
    wps: bool

    @property
    def wep_era(self) -> bool:
        """Privacy claimed with no WPA/WPA2 IE: a WEP-era security claim."""
        return self.privacy and self.rsn is None and not self.wpa1


def _frame_control(data: bytes, offset: int) -> tuple[int, int] | None:
    """Return ``(type, subtype)`` at ``offset`` or ``None`` when invalid."""
    if offset + 2 > len(data):
        return None
    first = data[offset]
    if first & 0x03 != 0:  # protocol version must be zero for 802.11-2007+
        return None
    return (first >> 2) & 0x03, (first >> 4) & 0x0F


def _management_offset(data: bytes) -> int | None:
    """Locate the start of the 802.11 management header.

    Handles both bare 802.11 frames and frames wrapped in a versioned link
    header (radiotap or PPI share the layout ``version, pad, length_le``).
    """
    direct = _frame_control(data, 0)
    if direct is not None and direct[0] == _MGMT_TYPE and direct[1] in _MGMT_SUBTYPES:
        if len(data) >= _MANAGEMENT_HEADER + _FIXED_PARAMETERS:
            return 0
        return None

    if len(data) < 8 or data[0] != 0:
        return None
    header_length = int.from_bytes(data[2:4], "little")
    if not 8 <= header_length <= len(data) - _MANAGEMENT_HEADER - _FIXED_PARAMETERS:
        return None
    wrapped = _frame_control(data, header_length)
    if wrapped is None or wrapped[0] != _MGMT_TYPE or wrapped[1] not in _MGMT_SUBTYPES:
        return None
    return header_length


def _mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def _parse_rsn(value: bytes) -> RsnInfo | None:
    """Parse an RSN information element; ``None`` when structurally invalid."""
    if len(value) < 10 or value[0:2] != b"\x01\x00":
        return None
    pos = 2

    if len(value) < pos + 4:
        return None
    group_type = value[pos + 3]
    pos += 4

    if len(value) < pos + 1:
        return None
    pairwise_count = value[pos]
    pos += 1
    if len(value) < pos + pairwise_count * 4:
        return None
    pairwise = tuple(value[pos + index * 4 + 3] for index in range(pairwise_count))
    pos += pairwise_count * 4

    if len(value) < pos + 1:
        return None
    akm_count = value[pos]
    pos += 1
    if len(value) < pos + akm_count * 4:
        return None
    akm = tuple(value[pos + index * 4 + 3] for index in range(akm_count))
    pos += akm_count * 4

    capabilities = 0
    if len(value) >= pos + 2:
        capabilities = int.from_bytes(value[pos : pos + 2], "little")
    return RsnInfo(
        akm_types=akm,
        pairwise_types=pairwise,
        group_type=group_type,
        mfpc=bool(capabilities & _RSN_CAPABILITY_MFPC),
        mfpr=bool(capabilities & _RSN_CAPABILITY_MFPR),
    )


def parse_frame(raw: bytes) -> BeaconInfo | None:
    """Parse a captured beacon or probe-response frame.

    Returns ``None`` for anything that is not a complete management frame of
    those two subtypes. Malformed input never raises: partial information
    elements are simply not reported.
    """
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        return None
    data = bytes(raw)
    if len(data) < _MANAGEMENT_HEADER + _FIXED_PARAMETERS:
        return None

    offset = _management_offset(data)
    if offset is None:
        return None

    control = _frame_control(data, offset)
    assert control is not None  # guaranteed by _management_offset
    subtype = control[1]
    header_length = _MANAGEMENT_HEADER
    if data[offset + 1] & _FRAME_CONTROL_ORDER:
        header_length += 4  # HT Control field present

    body = offset + header_length
    if len(data) < body + _FIXED_PARAMETERS:
        return None

    beacon_interval = int.from_bytes(data[body + 8 : body + 10], "little")
    capability = int.from_bytes(data[body + 10 : body + 12], "little")
    bssid = _mac(data[offset + 16 : offset + 22])  # address 3 identifies the AP

    ssid: str | None = None
    hidden = False
    channel: int | None = None
    rsn: RsnInfo | None = None
    wpa1 = False
    wps = False
    ssid_seen = False

    pos = body + _FIXED_PARAMETERS
    while pos + 2 <= len(data):
        tag = data[pos]
        length = data[pos + 1]
        end = pos + 2 + length
        if end > len(data):
            break  # truncated trailing element: keep everything parsed so far
        value = data[pos + 2 : end]

        if tag == _IE_SSID:
            ssid_seen = True
            if value:
                ssid = value.decode("utf-8", errors="replace")
            else:
                hidden = True
        elif tag == _IE_DS_PARAMETER and value:
            channel = value[0]
        elif tag == _IE_RSN:
            parsed = _parse_rsn(value)
            if parsed is not None:
                rsn = parsed
        elif tag == _IE_VENDOR and len(value) >= 4:
            oui, ie_type = value[0:3], value[3]
            if oui == _MICROSOFT_OUI and ie_type == _WPA1_IE_TYPE:
                wpa1 = True
            if ie_type == _WPS_IE_TYPE and oui in (_MICROSOFT_OUI, _WFA_OUI):
                wps = True
        pos = end

    return BeaconInfo(
        bssid=bssid,
        frame_kind="beacon" if subtype == _BEACON_SUBTYPE else "probe_response",
        ssid=ssid,
        hidden=hidden or not ssid_seen,
        channel=channel,
        beacon_interval=beacon_interval,
        privacy=bool(capability & _PRIVACY_CAPABILITY),
        rsn=rsn,
        wpa1=wpa1,
        wps=wps,
    )
