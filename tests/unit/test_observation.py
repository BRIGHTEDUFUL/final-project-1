"""Unit tests for the network observation model."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.models import ModelValidationError, NetworkObservation, SecurityMode


def test_defaults_are_safe() -> None:
    observation = NetworkObservation(ssid="HomeNet")
    assert observation.id is None
    assert observation.bssid is None
    assert observation.signal_strength is None
    assert observation.security is None
    assert observation.channel is None
    assert observation.observed_at.tzinfo is not None
    assert observation.ssid == "HomeNet"
    assert observation.security_mode is None


def test_requires_identity() -> None:
    with pytest.raises(ModelValidationError):
        NetworkObservation()


def test_hidden_network_is_detected() -> None:
    observation = NetworkObservation(bssid="aa:bb:cc:dd:ee:ff")
    assert observation.is_hidden
    assert observation.identity == "aa:bb:cc:dd:ee:ff"


def test_identity_combines_ssid_and_bssid() -> None:
    observation = NetworkObservation(ssid="HomeNet", bssid="AA-BB-CC-DD-EE-FF")
    assert observation.bssid == "aa:bb:cc:dd:ee:ff"
    assert observation.identity == "HomeNet [aa:bb:cc:dd:ee:ff]"


def test_empty_ssid_is_treated_as_hidden() -> None:
    assert NetworkObservation(ssid="", bssid="aa:bb:cc:dd:ee:ff").ssid is None


def test_ssid_whitespace_is_preserved_exactly() -> None:
    """A SSID is an opaque byte string: surrounding spaces are significant."""
    assert NetworkObservation(ssid="  Home  ", bssid="aa:bb:cc:dd:ee:ff").ssid == "  Home  "


@pytest.mark.parametrize("bad_signal", [-1, 101, "90", 90.5, True])
def test_invalid_signal_is_rejected(bad_signal: object) -> None:
    with pytest.raises(ModelValidationError):
        NetworkObservation(ssid="x", signal_strength=bad_signal)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_channel", [0, 256, "6"])
def test_invalid_channel_is_rejected(bad_channel: object) -> None:
    with pytest.raises(ModelValidationError):
        NetworkObservation(ssid="x", channel=bad_channel)  # type: ignore[arg-type]


def test_invalid_bssid_is_rejected_as_validation_error() -> None:
    with pytest.raises(ModelValidationError):
        NetworkObservation(ssid="x", bssid="nonsense")


def test_naive_datetime_is_treated_as_utc() -> None:
    naive = datetime(2026, 1, 1, 12, 0, 0)
    observation = NetworkObservation(ssid="x", observed_at=naive)
    assert observation.observed_at == datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def test_iso_string_datetime_is_parsed() -> None:
    observation = NetworkObservation(ssid="x", observed_at="2026-01-01T12:00:00+02:00")
    assert observation.observed_at == datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)


def test_invalid_datetime_is_rejected() -> None:
    with pytest.raises(ModelValidationError):
        NetworkObservation(ssid="x", observed_at="not-a-date")


def test_model_is_immutable() -> None:
    observation = NetworkObservation(ssid="x")
    with pytest.raises((AttributeError, TypeError)):
        observation.ssid = "y"  # type: ignore[misc]


def test_round_trip_dict() -> None:
    original = NetworkObservation(
        id=7,
        ssid="HomeNet",
        bssid="aa:bb:cc:dd:ee:ff",
        signal_strength=86,
        security="WPA2-Personal",
        channel=11,
        observed_at=datetime(2026, 3, 1, 8, 30, tzinfo=UTC),
    )
    restored = NetworkObservation.from_dict(original.to_dict())
    assert restored == original
    assert restored.security_mode is SecurityMode.WPA2


def test_from_dict_requires_mapping() -> None:
    with pytest.raises(ModelValidationError):
        NetworkObservation.from_dict(["not", "a", "map"])  # type: ignore[arg-type]


def test_signal_stability_for_detection_history() -> None:
    """Observations taken a moment apart keep independent timestamps."""
    first = NetworkObservation(ssid="x", observed_at=datetime(2026, 1, 1, tzinfo=UTC))
    second = NetworkObservation(ssid="x", observed_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=5))
    assert second.observed_at > first.observed_at
