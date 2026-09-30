"""Unit tests for trusted network, alert, scan session and setting models."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.models import (
    Alert,
    AlertStatus,
    AlertType,
    ApplicationSetting,
    ModelValidationError,
    ScanSession,
    ScanSessionStatus,
    SecurityMode,
    Severity,
    TrustedNetwork,
    normalize_bssid,
)

# ---------------------------------------------------------------- TrustedNetwork


def test_trusted_network_normalises_and_deduplicates() -> None:
    profile = TrustedNetwork(
        ssid="Office",
        approved_bssids=["AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"],
    )
    assert profile.approved_bssids == ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
    assert profile.approves("aa:bb:cc:dd:ee:ff")
    assert not profile.approves("ff:ee:dd:cc:bb:aa")
    assert not profile.approves(None)
    assert profile.knows_bssids


def test_trusted_network_requires_ssid() -> None:
    with pytest.raises(ModelValidationError):
        TrustedNetwork(ssid="   ")


def test_trusted_network_without_bssids_never_approves() -> None:
    profile = TrustedNetwork(ssid="Office")
    assert not profile.knows_bssids
    assert not profile.approves("aa:bb:cc:dd:ee:ff")


def test_expected_security_mode() -> None:
    profile = TrustedNetwork(ssid="Office", expected_security="WPA2-Personal")
    assert profile.expected_security_mode is SecurityMode.WPA2
    assert TrustedNetwork(ssid="Office").expected_security_mode is None


def test_trusted_network_round_trip() -> None:
    original = TrustedNetwork(
        id=3,
        ssid="Office",
        approved_bssids=("aa:bb:cc:dd:ee:ff",),
        expected_security="WPA3-SAE",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        notes="lab",
    )
    assert TrustedNetwork.from_dict(original.to_dict()) == original


# ---------------------------------------------------------------- Severity


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, Severity.LOW),
        (29, Severity.LOW),
        (30, Severity.SUSPICIOUS),
        (59, Severity.SUSPICIOUS),
        (60, Severity.HIGH),
        (79, Severity.HIGH),
        (80, Severity.CRITICAL),
        (100, Severity.CRITICAL),
    ],
)
def test_severity_bands(score: int, expected: Severity) -> None:
    assert Severity.from_score(score) is expected


def test_severity_clamps_out_of_range_scores() -> None:
    assert Severity.from_score(-10) is Severity.LOW
    assert Severity.from_score(500) is Severity.CRITICAL


def test_severity_rejects_bad_thresholds() -> None:
    with pytest.raises(ModelValidationError):
        Severity.from_score(50, (60, 30, 80))
    with pytest.raises(ModelValidationError):
        Severity.from_score(50, (30, 60))


def test_severity_rank_orders_bands() -> None:
    assert Severity.LOW.rank < Severity.SUSPICIOUS.rank < Severity.HIGH.rank < Severity.CRITICAL.rank


# ---------------------------------------------------------------- Alert


def test_alert_derives_severity_from_score() -> None:
    alert = Alert.from_score(
        ssid="Evil",
        bssid="aa:bb:cc:dd:ee:ff",
        alert_type=AlertType.SECURITY_DOWNGRADE,
        risk_score=72,
        reasons=["security downgrade: WPA2 -> Open"],
    )
    assert alert.severity is Severity.HIGH
    assert alert.status is AlertStatus.ACTIVE
    assert alert.is_open
    assert alert.evidence == "security downgrade: WPA2 -> Open"


def test_alert_normalises_bssid_and_single_reason() -> None:
    alert = Alert(ssid="Evil", bssid="AA-BB-CC-DD-EE-FF", alert_type="duplicate_ssid", reasons="dup")
    assert alert.bssid == "aa:bb:cc:dd:ee:ff"
    assert alert.reasons == ("dup",)
    assert alert.alert_type is AlertType.DUPLICATE_SSID


def test_alert_requires_identity() -> None:
    with pytest.raises(ModelValidationError):
        Alert(alert_type=AlertType.OTHER)


def test_alert_rejects_out_of_range_score() -> None:
    with pytest.raises(ModelValidationError):
        Alert(ssid="x", risk_score=101)
    with pytest.raises(ModelValidationError):
        Alert(ssid="x", risk_score=-1)


def test_alert_rejects_unknown_type() -> None:
    with pytest.raises(ModelValidationError):
        Alert(ssid="x", alert_type="made_up_type")


def test_alert_evidence_fallback() -> None:
    assert Alert(ssid="x").evidence == "no specific evidence recorded"


def test_alert_round_trip() -> None:
    original = Alert.from_score(
        ssid="Evil",
        bssid="aa:bb:cc:dd:ee:ff",
        alert_type=AlertType.DUPLICATE_SSID,
        risk_score=45,
        reasons=["duplicate ssid", "unknown bssid"],
        created_at=datetime(2026, 2, 2, tzinfo=UTC),
        id=12,
    )
    restored = Alert.from_dict(original.to_dict())
    assert restored == original


def test_alert_from_dict_requires_mapping() -> None:
    with pytest.raises(ModelValidationError):
        Alert.from_dict(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------- ScanSession


def test_scan_session_defaults() -> None:
    session = ScanSession()
    assert session.status is ScanSessionStatus.RUNNING
    assert session.network_count == 0
    assert not session.is_finished()
    assert session.completed_at is None


def test_scan_session_finish() -> None:
    session = ScanSession(started_at=datetime(2026, 1, 1, tzinfo=UTC))
    finished = session.finish(network_count=12)
    assert finished.status is ScanSessionStatus.COMPLETED
    assert finished.network_count == 12
    assert finished.completed_at is not None
    assert finished.is_finished()
    assert not session.is_finished()  # original untouched


def test_scan_session_finish_rejects_running_status() -> None:
    with pytest.raises(ModelValidationError):
        ScanSession().finish(ScanSessionStatus.RUNNING)


def test_scan_session_rejects_completed_before_started() -> None:
    with pytest.raises(ModelValidationError):
        ScanSession(
            started_at=datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
            completed_at=datetime(2026, 1, 1, 11, 0, tzinfo=UTC),
        )


def test_scan_session_rejects_negative_count() -> None:
    with pytest.raises(ModelValidationError):
        ScanSession(network_count=-1)


def test_scan_session_round_trip() -> None:
    original = ScanSession(
        id=2,
        started_at=datetime(2026, 1, 1, 8, 0, tzinfo=UTC),
        completed_at=datetime(2026, 1, 1, 8, 0, 5, tzinfo=UTC),
        network_count=9,
        status=ScanSessionStatus.COMPLETED,
    )
    assert ScanSession.from_dict(original.to_dict()) == original


# ---------------------------------------------------------------- ApplicationSetting


def test_setting_requires_key() -> None:
    with pytest.raises(ModelValidationError):
        ApplicationSetting(key="  ")


def test_setting_round_trip() -> None:
    original = ApplicationSetting(
        key="scan_interval_seconds",
        value="15",
        updated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert ApplicationSetting.from_dict(original.to_dict()) == original
    assert not original.is_empty
    assert ApplicationSetting(key="k").is_empty


def test_bssid_helper_is_reexported() -> None:
    assert normalize_bssid("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"


def test_alert_status_transitions_are_values() -> None:
    assert AlertStatus("acknowledged") is AlertStatus.ACKNOWLEDGED
    assert AlertStatus("resolved").value == "resolved"


def test_alert_time_is_utc_aware() -> None:
    alert = Alert(ssid="x", created_at=datetime(2026, 5, 5, 12, 0) - timedelta(hours=0))
    assert alert.created_at.tzinfo is not None
