"""Unit tests for frame-capture prerequisites and interface selection.

No pcap driver is required: availability checks and device classification
are exercised with injected fakes.
"""

from __future__ import annotations

import pytest

from app.capture import (
    CaptureError,
    CaptureInterface,
    FrameSource,
    check_availability,
    select_interface,
)
from app.capture import source as source_module

ETHERNET = CaptureInterface(
    name=r"\Device\NPF_{11111111-1111-1111-1111-111111111111}",
    description="Intel Ethernet Connection",
    friendly_name="Ethernet",
    flags=0,
)
WIFI = CaptureInterface(
    name=r"\Device\NPF_{22222222-2222-2222-2222-222222222222}",
    description="AX201 160MHz",
    friendly_name="Wi-Fi",
    flags=source_module._IF_WIRELESS,  # noqa: SLF001
)
WLAN = CaptureInterface(
    name=r"\Device\NPF_{33333333-3333-3333-3333-333333333333}",
    description="USB Wireless Adapter",
    friendly_name="WLAN",
    flags=source_module._IF_WIRELESS,  # noqa: SLF001
)
LOOPBACK = CaptureInterface(
    name=r"\Device\NPF_{44444444-4444-4444-4444-444444444444}",
    description="Npcap loopback adapter",
    friendly_name="Loopback",
    flags=source_module._IF_LOOPBACK,  # noqa: SLF001
)


# ------------------------------------------------------------- availability


def test_availability_requires_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(source_module.platform, "system", lambda: "Linux")

    availability = check_availability()

    assert availability.available is False
    assert "Windows" in availability.reason
    assert not availability


def test_availability_reports_missing_driver(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(source_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(source_module, "_load_wpcap", lambda: None)

    availability = check_availability()

    assert availability.available is False
    assert "Npcap" in availability.reason


def test_availability_is_ready_with_driver(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(source_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(source_module, "_load_wpcap", lambda: object())

    availability = check_availability()

    assert availability.available is True
    assert availability.reason == ""


# --------------------------------------------------------- interface picking


def test_select_interface_prefers_the_wi_fi_connection() -> None:
    chosen = select_interface([ETHERNET, WLAN, WIFI])

    assert chosen is WIFI


def test_select_interface_falls_back_to_any_wireless_device() -> None:
    chosen = select_interface([ETHERNET, WLAN])

    assert chosen is WLAN


def test_select_interface_returns_none_without_wireless() -> None:
    assert select_interface([ETHERNET, LOOPBACK]) is None


def test_select_interface_ignores_loopback_even_with_wireless_hint() -> None:
    wireless_loopback = CaptureInterface(
        name=r"\Device\NPF_{55555555-5555-5555-5555-555555555555}",
        description="wireless loopback test device",
        friendly_name="Loopback",
        flags=source_module._IF_LOOPBACK,  # noqa: SLF001
    )

    assert select_interface([wireless_loopback]) is None


def test_wireless_label_hint_classifies_flagless_devices() -> None:
    hinted = CaptureInterface(
        name=r"\Device\NPF_{66666666-6666-6666-6666-666666666666}",
        description="Realtek 8812BU Wi-Fi 5",
        friendly_name="Unknown",
        flags=0,
    )

    assert hinted.wireless is True


# ------------------------------------------------------------ device naming


def test_device_guid_extracted_from_npf_name() -> None:
    guid = source_module._device_guid(  # noqa: SLF001
        r"\Device\NPF_{9F8E7D6C-1A2B-3C4D-5E6F-708192A3B4C5}"
    )
    assert guid == "{9F8E7D6C-1A2B-3C4D-5E6F-708192A3B4C5}"
    assert source_module._device_guid(r"\Device\NPF_notaguid") is None  # noqa: SLF001
    assert (  # noqa: SLF001
        source_module._device_guid("{9F8E7D6C-1A2B-3C4D-5E6F-708192A3B4C5}")  # noqa: SLF001
        == "{9F8E7D6C-1A2B-3C4D-5E6F-708192A3B4C5}"
    )


# ---------------------------------------------------------------- start path


def test_start_without_driver_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(source_module, "_load_wpcap", lambda: None)
    source = FrameSource()

    with pytest.raises(CaptureError, match="driver not available"):
        source.start(lambda _raw: None)


def test_start_without_wireless_device_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(source_module, "_load_wpcap", lambda: object())
    monkeypatch.setattr(source_module, "_bind_api", lambda _handle: None)
    source = FrameSource(lister=lambda _api: [ETHERNET, LOOPBACK])

    with pytest.raises(CaptureError, match="wireless capture interface"):
        source.start(lambda _raw: None)


def test_stop_before_start_is_safe() -> None:
    source = FrameSource()

    source.stop()

    assert source.running is False
    assert source.interface is None
