"""Session-level beacon tracking and evidence enrichment.

The observer turns parsed beacon frames into a small in-memory index keyed
by BSSID and, when an alert is written, appends observable evidence lines
(WPS advertised, PMF absent, hidden SSID, ...) to that alert's reasons.
Evidence lines never change the risk score: weights stay the exclusive,
documented research parameters.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from app.capture.beacons import BeaconInfo, parse_frame
from app.capture.source import (
    CAPABLE_LINKTYPES,
    CaptureAvailability,
    FrameSource,
    check_availability,
)
from app.models import utcnow

logger = logging.getLogger(__name__)

__all__ = ["FrameObserver", "FrameRecord", "ObserverState"]

_BSSID_SEPARATORS = str.maketrans({"-": ":", ".": ":"})


class ObserverState(StrEnum):
    """Lifecycle state of the frame observer."""

    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class FrameRecord:
    """Aggregated beacon history for one BSSID within this session."""

    info: BeaconInfo
    first_seen: datetime
    last_seen: datetime
    beacon_count: int


def _normalize_bssid(value: str | None) -> str | None:
    """Return a canonical lowercase ``aa:bb:cc:dd:ee:ff`` or ``None``."""
    if not isinstance(value, str):
        return None
    candidate = value.strip().translate(_BSSID_SEPARATORS).lower()
    parts = candidate.split(":")
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        return None
    if any(any(char not in "0123456789abcdef" for char in part) for part in parts):
        return None
    return candidate


def _evidence_lines(info: BeaconInfo) -> tuple[str, ...]:
    """Observable, non-accusatory facts drawn from one AP's beacons."""
    lines: list[str] = []
    if info.wep_era:
        lines.append(
            "beacon: privacy capability set with no WPA/WPA2 element (WEP-era security)"
        )
    if info.wpa1:
        lines.append("beacon: legacy WPA1 information element present")
    if info.wps:
        lines.append("beacon: WPS configuration interface advertised")
    if info.rsn is not None and not info.rsn.mfpr:
        if info.rsn.mfpc:
            lines.append("beacon: 802.11w management frame protection optional, not required")
        else:
            lines.append("beacon: 802.11w management frame protection not in use")
    if info.hidden:
        lines.append("beacon: SSID withheld in broadcast frames (hidden network)")
    if info.rsn is not None and info.rsn.uses_sae:
        lines.append("beacon: SAE (WPA3) authentication advertised")
    return tuple(lines)


class FrameObserver:
    """Tracks beacon frames for one application session.

    ``start`` never raises: environmental problems (missing Npcap driver,
    no wireless capture interface, permission denied) become the ``error``
    or ``unavailable`` state with a human-readable detail, and the rest of
    the application keeps running on netsh evidence alone.
    """

    MAX_EVIDENCE_LINES = 4

    def __init__(
        self,
        *,
        enabled: bool = True,
        source: FrameSource | None = None,
        availability: Callable[[], CaptureAvailability] | None = None,
    ) -> None:
        self._enabled = bool(enabled)
        self._source = source if source is not None else FrameSource()
        self._availability = availability if availability is not None else check_availability
        self._records: dict[str, FrameRecord] = {}
        self._lock = threading.Lock()
        self._state = ObserverState.DISABLED
        self._detail = "not started"
        self._running = False

    # ---------------------------------------------------------------- state

    @property
    def state(self) -> ObserverState:
        """Current lifecycle state."""
        return self._state

    @property
    def detail(self) -> str:
        """Human-readable detail accompanying :attr:`state`."""
        return self._detail

    @property
    def enabled(self) -> bool:
        """``True`` while the observer is switched on in configuration."""
        return self._enabled

    @property
    def observed_count(self) -> int:
        """Number of distinct BSSIDs seen in beacon frames this session."""
        with self._lock:
            return len(self._records)

    def status_text(self) -> str:
        """One-line status for the settings page and logs."""
        state = self._state
        if state is ObserverState.RUNNING:
            link = self._source.datalink
            if link is not None and link not in CAPABLE_LINKTYPES:
                return (
                    "running, but the adapter exposes link type "
                    f"{link} (no 802.11 beacons to analyse)"
                )
            count = self.observed_count
            noun = "BSSID" if count == 1 else "BSSIDs"
            return f"running \u2014 {count} {noun} observed in beacons"
        return f"{state.value} \u2014 {self._detail}" if self._detail else state.value

    # ------------------------------------------------------------- lifecycle

    def start(self) -> None:
        """Begin capturing if enabled and available; idempotent, never raises."""
        if not self._enabled:
            self._set_state(ObserverState.DISABLED, "switched off in settings")
            return
        if self._running:
            return

        availability = self._availability()
        if not availability.available:
            self._set_state(ObserverState.UNAVAILABLE, availability.reason or "unavailable")
            return

        try:
            self._source.start(self.ingest, on_error=self._on_source_error)
        except Exception as exc:
            logger.warning("frame observer could not start: %s", exc)
            self._set_state(ObserverState.ERROR, str(exc))
            return
        self._running = True
        self._set_state(ObserverState.RUNNING, "capturing broadcast management frames")

    def stop(self) -> None:
        """Stop capturing; keeps collected evidence for the session."""
        if not self._running:
            return
        self._running = False
        try:
            self._source.stop()
        except Exception:
            logger.exception("frame observer source did not stop cleanly")
            self._set_state(ObserverState.ERROR, "capture did not stop cleanly")
            return
        self._set_state(ObserverState.STOPPED, "stopped by the application")

    def set_enabled(self, enabled: bool) -> None:
        """Apply the configuration toggle, starting or stopping as needed."""
        enabled = bool(enabled)
        if enabled == self._enabled:
            return
        self._enabled = enabled
        if enabled:
            self.start()
        else:
            self.stop()
            self._set_state(ObserverState.DISABLED, "switched off in settings")

    # ---------------------------------------------------------------- data

    def ingest(self, raw: bytes) -> None:
        """Parse one captured frame and record it; called per frame."""
        info = parse_frame(raw)
        if info is None:
            return
        moment = utcnow()
        with self._lock:
            existing = self._records.get(info.bssid)
            if existing is None:
                self._records[info.bssid] = FrameRecord(
                    info=info,
                    first_seen=moment,
                    last_seen=moment,
                    beacon_count=1,
                )
            else:
                self._records[info.bssid] = FrameRecord(
                    info=info,
                    first_seen=existing.first_seen,
                    last_seen=moment,
                    beacon_count=existing.beacon_count + 1,
                )

    def enrich(self, bssid: str | None) -> tuple[str, ...]:
        """Return evidence lines for ``bssid`` (empty when nothing was seen)."""
        key = _normalize_bssid(bssid)
        if key is None:
            return ()
        with self._lock:
            record = self._records.get(key)
        if record is None:
            return ()
        return _evidence_lines(record.info)[: self.MAX_EVIDENCE_LINES]

    # ------------------------------------------------------------- internals

    def _on_source_error(self, message: str) -> None:
        """Capture-thread failure: surface it instead of pretending to run."""
        self._running = False
        self._set_state(ObserverState.ERROR, message)

    def _set_state(self, state: ObserverState, detail: str) -> None:
        if state is not self._state or detail != self._detail:
            logger.debug("frame observer: %s (%s)", state.value, detail)
        self._state = state
        self._detail = detail
