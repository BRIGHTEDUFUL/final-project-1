"""Unit tests for the frame observer lifecycle and evidence enrichment.

Everything runs against a fake frame source: no driver, no radio.
"""

from __future__ import annotations

from app.capture import CaptureAvailability, CaptureError, FrameObserver, ObserverState
from tests.support import (
    MICROSOFT_OUI,
    FakeFrameSource,
    build_beacon,
    rsn_ie,
    vendor_ie,
)

BSSID = "aa:bb:cc:dd:ee:ff"
BSSID_UPPER = "AA:BB:CC:DD:EE:FF"


def _available() -> CaptureAvailability:
    return CaptureAvailability(True)


def _unavailable() -> CaptureAvailability:
    return CaptureAvailability(False, "Npcap/WinPcap driver not found")


def _observer(
    *,
    enabled: bool = True,
    availability=_available,
    source: FakeFrameSource | None = None,
) -> tuple[FrameObserver, FakeFrameSource]:
    fake = source if source is not None else FakeFrameSource()
    observer = FrameObserver(enabled=enabled, source=fake, availability=availability)
    return observer, fake


# ------------------------------------------------------------------ lifecycle


def test_disabled_observer_never_starts_the_source() -> None:
    observer, source = _observer(enabled=False)

    observer.start()

    assert observer.state is ObserverState.DISABLED
    assert source.started is False
    assert "disabled" in observer.status_text()


def test_missing_driver_reports_unavailable_with_reason() -> None:
    observer, source = _observer(availability=_unavailable)

    observer.start()

    assert observer.state is ObserverState.UNAVAILABLE
    assert "Npcap" in observer.detail
    assert "unavailable" in observer.status_text()
    assert source.started is False


def test_available_environment_starts_capture() -> None:
    observer, source = _observer()

    observer.start()

    assert observer.state is ObserverState.RUNNING
    assert source.started is True
    assert source.callback is not None
    assert "running" in observer.status_text()


def test_start_refusal_becomes_error_state() -> None:
    source = FakeFrameSource(
        start_error=CaptureError("no wireless capture interface is exposed by the driver")
    )
    observer, _ = _observer(source=source)

    observer.start()

    assert observer.state is ObserverState.ERROR
    assert "wireless capture interface" in observer.detail
    assert "error" in observer.status_text()


def test_stop_stops_the_source_and_keeps_state_visible() -> None:
    observer, source = _observer()
    observer.start()

    observer.stop()

    assert observer.state is ObserverState.STOPPED
    assert source.stopped is True


def test_source_thread_failure_surfaces_as_error() -> None:
    observer, source = _observer()
    observer.start()
    assert source.on_error is not None

    source.on_error("It is not yet possible to open the adapter")

    assert observer.state is ObserverState.ERROR
    assert "adapter" in observer.detail


def test_set_enabled_toggles_at_runtime() -> None:
    observer, source = _observer()
    observer.start()
    assert observer.state is ObserverState.RUNNING

    observer.set_enabled(False)
    assert observer.state is ObserverState.DISABLED
    assert source.stopped is True

    observer.set_enabled(True)
    assert observer.state is ObserverState.RUNNING
    assert source.callback is not None
    assert source.start_calls == 2


def test_set_enabled_with_same_value_is_a_noop() -> None:
    observer, source = _observer()
    observer.start()

    observer.set_enabled(True)

    assert source.start_calls == 1


def test_stop_before_start_is_safe() -> None:
    observer, source = _observer()

    observer.stop()

    assert source.stop_calls == 0
    assert observer.state is ObserverState.DISABLED


def test_non_capable_link_type_is_called_out_in_status() -> None:
    observer, source = _observer(source=FakeFrameSource(datalink=1))
    observer.start()

    status = observer.status_text()

    assert "link type 1" in status
    assert "no 802.11" in status


# ----------------------------------------------------------------------- data


def test_ingested_beacon_enriches_matching_bssid() -> None:
    observer, source = _observer()
    observer.start()
    source.feed(build_beacon(bssid=BSSID, ies=(vendor_ie(MICROSOFT_OUI, 4),)))

    lines = observer.enrich(BSSID_UPPER)  # case-insensitive lookup

    assert lines, "evidence expected for the observed BSSID"
    assert any("WPS" in line for line in lines)
    assert all(line.startswith("beacon:") for line in lines)
    assert observer.observed_count == 1


def test_unseen_or_invalid_bssid_enriches_to_nothing() -> None:
    observer, source = _observer()
    observer.start()

    assert observer.enrich("11:22:33:44:55:66") == ()
    assert observer.enrich("not-a-bssid") == ()
    assert observer.enrich(None) == ()


def test_non_beacon_bytes_are_ignored() -> None:
    observer, source = _observer()
    observer.start()

    source.feed(build_beacon(frame_type=2, subtype=0))
    source.feed(b"\x00\x00\x08\x00" + b"\xaa" * 40)
    source.feed(b"too short")

    assert observer.observed_count == 0
    assert observer.enrich(BSSID) == ()


def test_evidence_lines_are_capped_and_unique() -> None:
    observer, source = _observer()
    observer.start()
    source.feed(
        build_beacon(
            bssid=BSSID,
            ssid=b"",  # hidden
            capability=0x0011,
            ies=(
                vendor_ie(MICROSOFT_OUI, 4),  # WPS
                vendor_ie(MICROSOFT_OUI, 1),  # WPA1
                rsn_ie(akm=(8,), caps=0),  # SAE without PMF
            ),
        )
    )

    lines = observer.enrich(BSSID)

    # WPA1 + WPS + PMF + hidden + SAE are all observable; only the first
    # MAX_EVIDENCE_LINES are attached to an alert.
    assert len(lines) == FrameObserver.MAX_EVIDENCE_LINES
    assert len(lines) == len(set(lines)), "no duplicate evidence lines"
    assert any("WPS" in line for line in lines)


def test_wep_era_privacy_is_reported() -> None:
    observer, source = _observer()
    observer.start()
    source.feed(build_beacon(bssid=BSSID, capability=0x0011))  # privacy, no WPA IE

    lines = observer.enrich(BSSID)

    assert any("WEP-era" in line for line in lines)


def test_evidence_never_asserts_malice() -> None:
    forbidden = ("malicious", "evil twin confirmed", "attacker", "confirmed rogue")
    observer, source = _observer()
    observer.start()
    source.feed(
        build_beacon(
            bssid=BSSID,
            ssid=b"",
            capability=0x0011,
            ies=(vendor_ie(MICROSOFT_OUI, 4), rsn_ie(akm=(8,), caps=0)),
        )
    )

    for line in observer.enrich(BSSID):
        lowered = line.lower()
        assert not any(word in lowered for word in forbidden), line


def test_sae_advertisement_is_reported_as_neutral_fact() -> None:
    observer, source = _observer()
    observer.start()
    source.feed(build_beacon(bssid=BSSID, ies=(rsn_ie(akm=(8,)),)))

    lines = observer.enrich(BSSID)

    assert any("SAE" in line for line in lines)


def test_records_survive_a_stop_start_cycle() -> None:
    observer, source = _observer()
    observer.start()
    source.feed(build_beacon(bssid=BSSID, ies=(vendor_ie(MICROSOFT_OUI, 4),)))

    observer.stop()
    observer.start()

    assert observer.enrich(BSSID), "session evidence must survive a restart"
    assert observer.observed_count == 1
