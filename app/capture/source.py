"""Frame capture through an installed Npcap/WinPcap driver (system DLL only).

This layer deliberately uses no third-party Python packages: it talks to the
system ``wpcap.dll`` with ctypes, so the project keeps its free-tool,
permissive-license and offline-first guarantees. Nothing is bundled or
redistributed -- the driver must already be present on the machine (the free
Npcap installer). Only broadcast management frames are requested, via a BPF
filter where the link type supports one; the parser rejects everything else.
"""

from __future__ import annotations

import ctypes
import logging
import platform
import re
import threading
from collections.abc import Callable, Sequence
from ctypes import wintypes
from dataclasses import dataclass

logger = logging.getLogger(__name__)

__all__ = [
    "CaptureAvailability",
    "CaptureError",
    "CaptureInterface",
    "FrameSource",
    "check_availability",
    "select_interface",
]

PCAP_ERRBUF_SIZE = 256
_SNAPLEN = 65535
_OPEN_TIMEOUT_MS = 500  # keeps the loop responsive to stop() on idle networks

_IF_LOOPBACK = 0x00000001
_IF_WIRELESS = 0x00000002  # PCAP_IF_WIRELESS
_WIRELESS_HINTS = ("wi-fi", "wifi", "wlan", "wireless")

#: Link types whose payload the beacon parser understands.
CAPABLE_LINKTYPES = frozenset({105, 119, 127, 192})  # 802.11, prism, radiotap, PPI
DLT_ETHERNET = 1

_NPF_PREFIX = r"\Device\NPF_"
_GUID_PATTERN = re.compile(r"\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}")
_NETWORK_CLASS_KEY = (
    r"SYSTEM\CurrentControlSet\Control\Network"
    r"\{4D36E972-E325-11CE-BFC1-08002BE10318}"
)

_MANAGEMENT_FILTER = b"type mgt subtype beacon-probe-resp"


class CaptureError(RuntimeError):
    """Raised when the frame source cannot start or fails while capturing."""


@dataclass(frozen=True, slots=True)
class CaptureAvailability:
    """Prerequisite check for frame capture (prerequisites only, never data)."""

    available: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.available


@dataclass(frozen=True, slots=True)
class CaptureInterface:
    """One capture device exposed by the driver."""

    name: str  # pcap device name, e.g. \Device\NPF_{GUID}
    description: str
    friendly_name: str  # Windows connection name, e.g. "Wi-Fi"
    flags: int

    @property
    def wireless(self) -> bool:
        """``True`` when the device looks like a wireless adapter."""
        return _is_wireless(self.flags, self.friendly_name, self.description, self.name)


# --------------------------------------------------------------------- pcap C API


class _PcapIf(ctypes.Structure):
    pass


_PcapIf._fields_ = [  # noqa: SLF001 - ctypes requires the self-referential layout
    ("next", ctypes.POINTER(_PcapIf)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.c_void_p),
    ("flags", ctypes.c_uint32),
]


class _Timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]  # LLP64: 4 bytes


class _PcapPkthdr(ctypes.Structure):
    _fields_ = [
        ("ts", _Timeval),
        ("caplen", ctypes.c_uint32),
        ("len", ctypes.c_uint32),
    ]


class _BpfProgram(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint32), ("bf_insns", ctypes.c_void_p)]


def _load_wpcap() -> ctypes.CDLL | None:
    """Return a handle to the system pcap driver, or ``None`` when absent."""
    candidates: list[str] = []
    try:
        buffer = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
        length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, wintypes.MAX_PATH)
        if 0 < length < wintypes.MAX_PATH:
            system = buffer.value.rstrip("\\")
            candidates.extend([rf"{system}\wpcap.dll", rf"{system}\Npcap\wpcap.dll"])
    except (OSError, AttributeError):  # pragma: no cover - unusual environments
        logger.debug("system directory lookup failed; using the standard DLL search")
    candidates.append("wpcap.dll")

    for candidate in candidates:
        try:
            return ctypes.WinDLL(candidate)
        except OSError:
            continue
    return None


@dataclass(frozen=True, slots=True)
class _PcapApi:
    """Bound pcap entry points with explicit ctypes signatures."""

    findalldevs: Callable[..., int]
    freealldevs: Callable[..., None]
    open_live: Callable[..., ctypes.c_void_p]
    close: Callable[..., None]
    next_ex: Callable[..., int]
    datalink: Callable[..., int]
    geterr: Callable[..., int]
    compile: Callable[..., int]
    setfilter: Callable[..., int]
    freecode: Callable[..., None]


def _bind_api(handle: ctypes.CDLL) -> _PcapApi:
    errbuf = ctypes.POINTER(ctypes.c_char)

    handle.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(_PcapIf)), errbuf]
    handle.pcap_findalldevs.restype = ctypes.c_int
    handle.pcap_freealldevs.argtypes = [ctypes.POINTER(_PcapIf)]
    handle.pcap_freealldevs.restype = None
    handle.pcap_open_live.argtypes = [
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        errbuf,
    ]
    handle.pcap_open_live.restype = ctypes.c_void_p
    handle.pcap_close.argtypes = [ctypes.c_void_p]
    handle.pcap_close.restype = None
    handle.pcap_next_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(_PcapPkthdr)),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
    ]
    handle.pcap_next_ex.restype = ctypes.c_int
    handle.pcap_datalink.argtypes = [ctypes.c_void_p]
    handle.pcap_datalink.restype = ctypes.c_int
    handle.pcap_geterr.argtypes = [ctypes.c_void_p]
    handle.pcap_geterr.restype = ctypes.POINTER(ctypes.c_char)
    handle.pcap_compile.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_BpfProgram),
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_uint32,
    ]
    handle.pcap_compile.restype = ctypes.c_int
    handle.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BpfProgram)]
    handle.pcap_setfilter.restype = ctypes.c_int
    handle.pcap_freecode.argtypes = [ctypes.POINTER(_BpfProgram)]
    handle.pcap_freecode.restype = None

    return _PcapApi(
        findalldevs=handle.pcap_findalldevs,
        freealldevs=handle.pcap_freealldevs,
        open_live=handle.pcap_open_live,
        close=handle.pcap_close,
        next_ex=handle.pcap_next_ex,
        datalink=handle.pcap_datalink,
        geterr=handle.pcap_geterr,
        compile=handle.pcap_compile,
        setfilter=handle.pcap_setfilter,
        freecode=handle.pcap_freecode,
    )


# ------------------------------------------------------------ interface discovery


def _is_wireless(flags: int, *labels: str) -> bool:
    """Classify a capture device from its flags and human-readable labels."""
    if flags & _IF_LOOPBACK:
        return False
    if flags & _IF_WIRELESS:
        return True
    for label in labels:
        lowered = (label or "").lower()
        if any(hint in lowered for hint in _WIRELESS_HINTS):
            return True
    return False


def _device_guid(device_name: str) -> str | None:
    """Extract ``{GUID}`` from a ``\\Device\\NPF_{GUID}`` pcap device name."""
    suffix = device_name[len(_NPF_PREFIX) :] if device_name.startswith(_NPF_PREFIX) else device_name
    return suffix if _GUID_PATTERN.fullmatch(suffix) else None


def _registry_friendly_name(guid: str) -> str | None:
    """Map an adapter GUID to its connection name (e.g. ``Wi-Fi``)."""
    try:
        import winreg
    except ImportError:  # pragma: no cover - Windows-only module
        return None
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, rf"{_NETWORK_CLASS_KEY}\{guid}\Name"
        ) as key:
            value, _kind = winreg.QueryValueEx(key, "Name")
    except OSError:
        return None
    return str(value) if value else None


def _list_interfaces(api: _PcapApi) -> list[CaptureInterface]:
    """Enumerate capture devices with their Windows-friendly names."""
    all_devices = ctypes.POINTER(_PcapIf)()
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    if api.findalldevs(ctypes.byref(all_devices), errbuf) != 0:
        detail = errbuf.value.decode("utf-8", errors="replace")
        raise CaptureError(f"could not list capture devices: {detail}")

    interfaces: list[CaptureInterface] = []
    try:
        node = all_devices
        while node:
            entry = node.contents
            name = (entry.name or "").decode("utf-8", errors="replace")
            description = (entry.description or "").decode("utf-8", errors="replace")
            guid = _device_guid(name)
            friendly = (_registry_friendly_name(guid) if guid else None) or description or name
            interfaces.append(
                CaptureInterface(
                    name=name,
                    description=description,
                    friendly_name=friendly,
                    flags=int(entry.flags),
                )
            )
            node = entry.next
    finally:
        api.freealldevs(all_devices)
    return interfaces


def select_interface(interfaces: Sequence[CaptureInterface]) -> CaptureInterface | None:
    """Pick the wireless interface most likely to carry the Wi-Fi association."""
    wireless = [item for item in interfaces if item.wireless]
    if not wireless:
        return None
    for item in wireless:
        if item.friendly_name.lower().startswith("wi-fi"):
            return item
    return wireless[0]


def check_availability() -> CaptureAvailability:
    """Check the two prerequisites: Windows and an installed pcap driver."""
    if platform.system() != "Windows":
        return CaptureAvailability(
            False, "frame capture requires Windows; netsh monitoring continues to work"
        )
    if _load_wpcap() is None:
        return CaptureAvailability(
            False,
            "Npcap/WinPcap driver not found; install the free Npcap driver to enable frame analysis",
        )
    return CaptureAvailability(True)


# ------------------------------------------------------------------ frame source


class FrameSource:
    """Sniffs beacon/probe-response frames from one wireless interface.

    The capture loop runs on a dedicated daemon thread; ``pcap_next_ex``
    uses a short read timeout so :meth:`stop` returns promptly even on an
    idle network. Failures are reported through ``on_error`` or raised from
    :meth:`start` -- never swallowed silently.
    """

    def __init__(
        self,
        *,
        interface: str | None = None,
        lister: Callable[[_PcapApi], list[CaptureInterface]] | None = None,
    ) -> None:
        self._preferred = interface
        self._lister = lister or _list_interfaces
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._interface: str | None = None
        self._datalink: int | None = None
        self._on_frame: Callable[[bytes], None] | None = None
        self._on_error: Callable[[str], None] | None = None

    @property
    def interface(self) -> str | None:
        """pcap device name currently in use, or ``None`` before a start."""
        return self._interface

    @property
    def datalink(self) -> int | None:
        """Link type reported by the driver once the device is open."""
        return self._datalink

    @property
    def running(self) -> bool:
        """``True`` while the capture thread is alive."""
        thread = self._thread
        return thread is not None and thread.is_alive()

    def start(
        self,
        on_frame: Callable[[bytes], None],
        *,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        """Open the chosen device and start capturing; raises on refusal."""
        if self.running:
            raise CaptureError("frame source is already running")

        handle = _load_wpcap()
        if handle is None:
            raise CaptureError("Npcap/WinPcap driver not available")
        api = _bind_api(handle)

        interfaces = self._lister(api)
        chosen = None
        if self._preferred is not None:
            chosen = next((i for i in interfaces if i.name == self._preferred), None)
        if chosen is None:
            chosen = select_interface(interfaces)
        if chosen is None:
            raise CaptureError("no wireless capture interface is exposed by the driver")

        self._interface = chosen.name
        self._datalink = None
        self._stop.clear()
        self._on_frame = on_frame
        self._on_error = on_error
        self._thread = threading.Thread(
            target=self._run,
            args=(api, chosen.name),
            name="rogue-ap-frames",
            daemon=True,
        )
        self._thread.start()
        logger.debug("frame capture started on %s (%s)", chosen.friendly_name, chosen.name)

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the capture thread and wait briefly for it to exit."""
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is None:
            return
        thread.join(timeout)
        if thread.is_alive():  # pragma: no cover - depends on driver timing
            logger.warning("frame capture thread still stopping after %.1fs", timeout)
        self._on_frame = None
        self._on_error = None

    # ------------------------------------------------------------- internals

    def _run(self, api: _PcapApi, device: str) -> None:
        errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        pcap = api.open_live(device.encode("utf-8", errors="replace"), _SNAPLEN, 1, _OPEN_TIMEOUT_MS, errbuf)
        if not pcap:
            self._report_error(
                f"could not open {device}: {errbuf.value.decode('utf-8', errors='replace')}"
            )
            return

        try:
            self._datalink = int(api.datalink(pcap))
            self._install_filter(api, pcap)
            header = ctypes.POINTER(_PcapPkthdr)()
            data = ctypes.POINTER(ctypes.c_ubyte)()
            while not self._stop.is_set():
                result = api.next_ex(pcap, ctypes.byref(header), ctypes.byref(data))
                if result == 0:
                    continue  # read timeout: re-check the stop flag
                if result == -2:
                    break  # end of file (offline capture; not expected live)
                if result == -1:
                    raise CaptureError(self._error_text(api, pcap))
                self._dispatch(bytes(ctypes.string_at(data, header.contents.caplen)))
        except CaptureError as exc:
            self._report_error(str(exc))
        except Exception:
            logger.exception("frame capture loop failed")
            self._report_error("frame capture loop failed unexpectedly; see the log")
        finally:
            api.close(pcap)

    def _install_filter(self, api: _PcapApi, pcap: ctypes.c_void_p) -> None:
        """Ask the driver for management frames only; fall back gracefully."""
        program = _BpfProgram()
        if api.compile(pcap, ctypes.byref(program), _MANAGEMENT_FILTER, 1, 0xFFFFFFFF) != 0:
            # Not every link type knows the 802.11 primitives; the parser
            # still rejects anything that is not a beacon or probe response.
            logger.debug("pcap filter rejected for this link type; filtering in-process")
            return
        try:
            if api.setfilter(pcap, ctypes.byref(program)) != 0:
                logger.info("pcap setfilter failed: %s", self._error_text(api, pcap))
        finally:
            api.freecode(ctypes.byref(program))

    def _error_text(self, api: _PcapApi, pcap: ctypes.c_void_p) -> str:
        message = api.geterr(pcap)
        if not message or not message[0]:
            return "pcap reported an unspecified capture error"
        return ctypes.string_at(message).decode("utf-8", errors="replace")

    def _dispatch(self, raw: bytes) -> None:
        callback = self._on_frame
        if callback is None:
            return
        try:
            callback(raw)
        except Exception:  # pragma: no cover - defensive
            logger.exception("frame observer callback failed; capture continues")

    def _report_error(self, message: str) -> None:
        logger.warning("frame capture stopped: %s", message)
        callback = self._on_error
        if callback is not None:
            try:
                callback(message)
            except Exception:  # pragma: no cover - defensive
                logger.exception("frame capture error callback failed")
