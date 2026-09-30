"""Unit tests for individual detection rules."""

from __future__ import annotations

from datetime import UTC, datetime

from app.core.config import Config, RiskWeights
from app.detection import (
    SUSPICIOUS_SIGNAL_THRESHOLD,
    DetectionContext,
    duplicate_ssid_rule,
    new_access_point_rule,
    security_downgrade_rule,
    suspicious_signal_rule,
    unknown_bssid_rule,
)
from app.models import NetworkObservation, TrustedNetwork

WEIGHTS = Config().risk_weights


def obs(**kwargs: object) -> NetworkObservation:
    defaults: dict = {
        "ssid": "HomeNet",
        "bssid": "aa:bb:cc:dd:ee:01",
        "signal_strength": 60,
        "security": "WPA2-Personal",
        "observed_at": datetime(2026, 6, 1, 10, 0, tzinfo=UTC),
    }
    defaults.update(kwargs)
    return NetworkObservation(**defaults)  # type: ignore[arg-type]


def profile(**kwargs: object) -> TrustedNetwork:
    defaults: dict = {"ssid": "HomeNet", "approved_bssids": ("aa:bb:cc:dd:ee:01",)}
    defaults.update(kwargs)
    return TrustedNetwork(**defaults)  # type: ignore[arg-type]


# ------------------------------------------------------------- duplicate SSID


def test_duplicate_ssid_flags_unapproved_radios() -> None:
    context = DetectionContext(
        observations=(
            obs(bssid="aa:bb:cc:dd:ee:01"),
            obs(bssid="aa:bb:cc:dd:ee:02"),
        ),
        trusted=(profile(),),
    )
    findings = duplicate_ssid_rule(context, WEIGHTS)
    assert len(findings) == 1  # the approved radio is not flagged
    finding = findings[0]
    assert finding.rule.value == "duplicate_ssid"
    assert finding.weight == 25
    assert finding.bssid == "aa:bb:cc:dd:ee:02"
    assert "aa:bb:cc:dd:ee:01" in finding.explanation or "2 different" in finding.explanation
    assert "legitimately share an SSID" in str(finding.evidence["note"])


def test_duplicate_ssid_without_profile_flags_all() -> None:
    context = DetectionContext(
        observations=(obs(bssid="aa:bb:cc:dd:ee:01"), obs(bssid="aa:bb:cc:dd:ee:02")),
    )
    findings = duplicate_ssid_rule(context, WEIGHTS)
    assert len(findings) == 2
    assert all(f.weight == 25 for f in findings)
    assert all("No trusted profile" in f.explanation for f in findings)


def test_single_bssid_is_not_duplicate() -> None:
    context = DetectionContext(observations=(obs(),))
    assert duplicate_ssid_rule(context, WEIGHTS) == []


def test_hidden_ssid_duplicates_are_ignored() -> None:
    context = DetectionContext(
        observations=(obs(ssid=None, bssid="aa:bb:cc:dd:ee:01"), obs(ssid=None, bssid="aa:bb:cc:dd:ee:02")),
    )
    assert duplicate_ssid_rule(context, WEIGHTS) == []


def test_fully_approved_duplicate_produces_nothing() -> None:
    context = DetectionContext(
        observations=(obs(bssid="aa:bb:cc:dd:ee:01"), obs(bssid="aa:bb:cc:dd:ee:02")),
        trusted=(profile(approved_bssids=("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")),),
    )
    assert duplicate_ssid_rule(context, WEIGHTS) == []


# -------------------------------------------------------------- unknown BSSID


def test_unknown_bssid_for_trusted_network() -> None:
    context = DetectionContext(
        observations=(obs(bssid="ff:ee:dd:cc:bb:aa"),),
        trusted=(profile(),),
    )
    findings = unknown_bssid_rule(context, WEIGHTS)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule.value == "unknown_bssid"
    assert finding.weight == 20
    assert "not one of its 1 approved BSSIDs" in finding.explanation
    assert finding.evidence["approved_bssids"] == ["aa:bb:cc:dd:ee:01"]


def test_approved_bssid_is_not_flagged() -> None:
    context = DetectionContext(observations=(obs(),), trusted=(profile(),))
    assert unknown_bssid_rule(context, WEIGHTS) == []


def test_unknown_network_without_profile_is_not_flagged_by_this_rule() -> None:
    context = DetectionContext(observations=(obs(ssid="Stranger", bssid="ff:ee:dd:cc:bb:aa"),))
    assert unknown_bssid_rule(context, WEIGHTS) == []


def test_profile_without_bssids_disables_the_rule() -> None:
    context = DetectionContext(
        observations=(obs(bssid="ff:ee:dd:cc:bb:aa"),),
        trusted=(TrustedNetwork(ssid="HomeNet"),),
    )
    assert unknown_bssid_rule(context, WEIGHTS) == []


# ---------------------------------------------------------- security downgrade


def test_security_downgrade_is_detected() -> None:
    context = DetectionContext(
        observations=(obs(security="Open"),),
        trusted=(profile(expected_security="WPA2-Personal"),),
    )
    findings = security_downgrade_rule(context, WEIGHTS)
    assert len(findings) == 1
    assert findings[0].weight == 30
    assert findings[0].evidence["expected_mode"] == "wpa2"
    assert findings[0].evidence["observed_mode"] == "open"


def test_equal_or_stronger_security_is_fine() -> None:
    for observed in ("WPA2-Personal", "WPA3-SAE"):
        context = DetectionContext(
            observations=(obs(security=observed),),
            trusted=(profile(expected_security="WPA2-Personal"),),
        )
        assert security_downgrade_rule(context, WEIGHTS) == [], observed


def test_unreported_or_unknown_security_does_not_trigger() -> None:
    for observed in (None, "NotARealLabel"):
        context = DetectionContext(
            observations=(obs(security=observed),),
            trusted=(profile(expected_security="WPA2-Personal"),),
        )
        assert security_downgrade_rule(context, WEIGHTS) == [], observed


def test_no_expected_security_disables_the_rule() -> None:
    context = DetectionContext(observations=(obs(security="Open"),), trusted=(profile(),))
    assert security_downgrade_rule(context, WEIGHTS) == []


# ----------------------------------------------------------- new access point


def test_new_access_point_when_history_exists() -> None:
    context = DetectionContext(
        observations=(obs(bssid="ff:ee:dd:cc:bb:aa"),),
        known_bssids=frozenset({"aa:bb:cc:dd:ee:01"}),
    )
    findings = new_access_point_rule(context, WEIGHTS)
    assert len(findings) == 1
    assert findings[0].weight == 10
    assert findings[0].evidence["known_history_size"] == 1


def test_known_bssid_is_not_new() -> None:
    context = DetectionContext(
        observations=(obs(bssid="aa:bb:cc:dd:ee:01"),),
        known_bssids=frozenset({"aa:bb:cc:dd:ee:01"}),
    )
    assert new_access_point_rule(context, WEIGHTS) == []


def test_first_scan_without_history_suppresses_the_rule() -> None:
    context = DetectionContext(
        observations=(obs(bssid="ff:ee:dd:cc:bb:aa"),),
        history_available=False,
    )
    assert new_access_point_rule(context, WEIGHTS) == []


def test_duplicate_new_bssids_are_reported_once() -> None:
    context = DetectionContext(
        observations=(obs(bssid="ff:ee:dd:cc:bb:aa"), obs(bssid="ff:ee:dd:cc:bb:aa", signal_strength=70)),
    )
    findings = new_access_point_rule(context, WEIGHTS)
    assert len(findings) == 1


# ---------------------------------------------------------- suspicious signal


def test_strong_signal_from_unknown_radio_is_flagged() -> None:
    context = DetectionContext(
        observations=(obs(bssid="ff:ee:dd:cc:bb:aa", signal_strength=SUSPICIOUS_SIGNAL_THRESHOLD),),
    )
    findings = suspicious_signal_rule(context, WEIGHTS)
    assert len(findings) == 1
    assert findings[0].weight == 5


def test_out_signalling_the_connection_is_flagged() -> None:
    context = DetectionContext(
        observations=(obs(bssid="ff:ee:dd:cc:bb:aa", signal_strength=90),),
        connected_bssid="aa:bb:cc:dd:ee:01",
        connected_signal=60,
    )
    findings = suspicious_signal_rule(context, WEIGHTS)
    assert len(findings) == 1
    assert "exceeds the connected network's 60%" in findings[0].explanation


def test_approved_radio_is_never_flagged_by_signal_rule() -> None:
    context = DetectionContext(
        observations=(obs(bssid="aa:bb:cc:dd:ee:01", signal_strength=100),),
        trusted=(profile(),),
        connected_signal=50,
    )
    assert suspicious_signal_rule(context, WEIGHTS) == []


def test_moderate_known_signal_is_not_flagged() -> None:
    context = DetectionContext(
        observations=(obs(bssid="aa:bb:cc:dd:ee:01", signal_strength=50),),
        known_bssids=frozenset({"aa:bb:cc:dd:ee:01"}),
        connected_signal=60,
    )
    assert suspicious_signal_rule(context, WEIGHTS) == []


def test_signal_rule_requires_a_signal() -> None:
    context = DetectionContext(observations=(obs(bssid="ff:ee:dd:cc:bb:aa", signal_strength=None),))
    assert suspicious_signal_rule(context, WEIGHTS) == []


def test_signal_rule_requires_a_bssid() -> None:
    context = DetectionContext(observations=(obs(bssid=None, signal_strength=100),))
    assert suspicious_signal_rule(context, WEIGHTS) == []


def test_custom_weights_are_used() -> None:
    custom = RiskWeights(duplicate_ssid=77)
    context = DetectionContext(
        observations=(obs(bssid="aa:bb:cc:dd:ee:01"), obs(bssid="aa:bb:cc:dd:ee:02")),
    )
    findings = duplicate_ssid_rule(context, custom)
    assert all(f.weight == 77 for f in findings)
