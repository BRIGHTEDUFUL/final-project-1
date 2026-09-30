"""Passive 802.11 frame observation: the evidence layer below netsh.

Reads only broadcast management frames (beacon and probe-response) through
an installed Npcap driver. No transmission, no decryption, no client station
tracking -- the same passive guarantees as the scan path, one layer down.
"""

from __future__ import annotations

from app.capture.beacons import BeaconInfo, RsnInfo, parse_frame
from app.capture.observer import FrameObserver, FrameRecord, ObserverState
from app.capture.source import (
    CaptureAvailability,
    CaptureError,
    CaptureInterface,
    FrameSource,
    check_availability,
    select_interface,
)

__all__ = [
    "BeaconInfo",
    "CaptureAvailability",
    "CaptureError",
    "CaptureInterface",
    "FrameObserver",
    "FrameRecord",
    "FrameSource",
    "ObserverState",
    "RsnInfo",
    "check_availability",
    "parse_frame",
    "select_interface",
]
