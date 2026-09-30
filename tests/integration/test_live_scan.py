"""Live scan smoke check.

These tests use the real ``netsh`` command when a wireless interface exists.
They are skipped — never failed — on machines without WLAN support, so the
suite still passes on any Windows host, CI runner or Linux box.
"""

from __future__ import annotations

import pytest

from app.parser import parse_interfaces, parse_visible_networks_as_observations
from app.scanner import NetshScanner, ScannerError


@pytest.fixture(scope="module")
def scanner() -> NetshScanner:
    return NetshScanner()


def test_live_scan_produces_observations(scanner: NetshScanner) -> None:
    try:
        result = scanner.scan()
    except ScannerError as exc:
        pytest.skip(f"WLAN scanning unavailable: {exc}")

    if not result.ok:
        pytest.skip(f"scan command unavailable: {result.summary()}")

    observations = parse_visible_networks_as_observations(result.stdout)
    # Zero visible networks is legitimate; the call itself must simply work.
    assert isinstance(observations, list)
    for observation in observations:
        assert observation.bssid is None or ":" in observation.bssid


def test_live_interface_report_parses(scanner: NetshScanner) -> None:
    try:
        result = scanner.show_interfaces()
    except ScannerError as exc:
        pytest.skip(f"WLAN unavailable: {exc}")
    if not result.ok:
        pytest.skip(f"interface command unavailable: {result.summary()}")

    interfaces = parse_interfaces(result.stdout)
    assert isinstance(interfaces, list)
    for info in interfaces:
        assert info.name


def test_live_frame_observer_starts_and_stops() -> None:
    """Frame capture starts cleanly when Npcap is present, else skips."""
    import threading

    from app.capture import FrameObserver, ObserverState, check_availability

    availability = check_availability()
    if not availability.available:
        pytest.skip(f"frame capture unavailable: {availability.reason}")

    observer = FrameObserver()
    observer.start()
    try:
        if observer.state is ObserverState.UNAVAILABLE:
            pytest.skip(f"frame capture unavailable: {observer.detail}")
        if observer.state is ObserverState.ERROR:
            pytest.skip(f"capture refused by the driver: {observer.detail}")
        assert observer.state is ObserverState.RUNNING

        # Give the loop a moment; zero frames on an idle channel is fine.
        threading.Event().wait(0.3)
        assert isinstance(observer.status_text(), str)
    finally:
        observer.stop()
    assert observer.state in {ObserverState.STOPPED, ObserverState.ERROR}
