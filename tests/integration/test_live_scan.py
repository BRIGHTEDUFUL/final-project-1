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
