"""Unit tests for the detection engine and explainable risk scoring."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.config import Config
from app.detection import DetectionContext, DetectionEngine, Finding, FindingRule
from app.models import NetworkObservation, Severity, TrustedNetwork
from app.scoring import RiskScorer


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


def risky_context() -> DetectionContext:
    """One unapproved radio on a trusted name with a security downgrade."""
    return DetectionContext(
        observations=(
            obs(bssid="ff:ee:dd:cc:bb:aa", security="Open", signal_strength=99),
            obs(bssid="aa:bb:cc:dd:ee:01", security="WPA2-Personal", signal_strength=40),
        ),
        trusted=(
            TrustedNetwork(
                ssid="HomeNet",
                approved_bssids=("aa:bb:cc:dd:ee:01",),
                expected_security="WPA2-Personal",
            ),
        ),
        known_bssids=frozenset({"aa:bb:cc:dd:ee:01"}),
    )


# ---------------------------------------------------------------- engine


def test_engine_requires_valid_persistence_window() -> None:
    with pytest.raises(ValueError):
        DetectionEngine(persistence_scans=1)


def test_engine_finds_the_expected_indicators() -> None:
    engine = DetectionEngine(Config())
    report = engine.evaluate(risky_context())

    rules = {f.rule for f in report.findings}
    assert rules == {
        FindingRule.DUPLICATE_SSID,
        FindingRule.UNKNOWN_BSSID,
        FindingRule.SECURITY_DOWNGRADE,
        FindingRule.NEW_ACCESS_POINT,
        FindingRule.SUSPICIOUS_SIGNAL,
    }
    assert report.identity_count == 1  # every finding belongs to the unapproved radio


def test_clean_environment_produces_no_findings() -> None:
    engine = DetectionEngine(Config())
    context = DetectionContext(
        observations=(obs(bssid="aa:bb:cc:dd:ee:01"),),
        trusted=(
            TrustedNetwork(
                ssid="HomeNet",
                approved_bssids=("aa:bb:cc:dd:ee:01",),
                expected_security="WPA2-Personal",
            ),
        ),
        known_bssids=frozenset({"aa:bb:cc:dd:ee:01"}),
        connected_bssid="aa:bb:cc:dd:ee:01",
        connected_signal=60,
    )
    assert len(engine.evaluate(context)) == 0


def test_persistence_indicator_appears_after_consecutive_scans() -> None:
    engine = DetectionEngine(Config(), persistence_scans=3)
    context = risky_context()
    identity = ("HomeNet", "ff:ee:dd:cc:bb:aa")

    first = engine.evaluate(context)
    assert not any(f.rule is FindingRule.PERSISTENCE for f in first.findings)

    engine.evaluate(context)
    second_pass = engine.evaluate(context)

    persistence = [f for f in second_pass.findings if f.rule is FindingRule.PERSISTENCE]
    assert len(persistence) == 1
    assert persistence[0].ssid == "HomeNet"
    assert persistence[0].bssid == "ff:ee:dd:cc:bb:aa"
    assert persistence[0].weight == 10
    assert engine.persistence_counts[identity] == 3


def test_persistence_counter_resets_when_a_network_goes_clean() -> None:
    engine = DetectionEngine(Config(), persistence_scans=3)
    engine.evaluate(risky_context())
    engine.evaluate(risky_context())

    # A scan where the same identity produces no findings clears its counter.
    engine.evaluate(DetectionContext(observations=(obs(bssid="aa:bb:cc:dd:ee:01"),)))
    assert engine.persistence_counts.get(("HomeNet", "ff:ee:dd:cc:bb:aa")) is None

    engine.evaluate(risky_context())
    assert engine.persistence_counts[("HomeNet", "ff:ee:dd:cc:bb:aa")] == 1


def test_reset_clears_state() -> None:
    engine = DetectionEngine(Config(), persistence_scans=2)
    engine.evaluate(risky_context())
    engine.evaluate(risky_context())
    assert engine.persistence_counts
    engine.reset()
    assert engine.persistence_counts == {}


def test_with_config_preserves_persistence_state() -> None:
    engine = DetectionEngine(Config(), persistence_scans=3)
    engine.evaluate(risky_context())
    clone = engine.with_config(Config(scan_interval_seconds=30))
    assert clone.persistence_counts == engine.persistence_counts
    assert clone.config.scan_interval_seconds == 30


# ---------------------------------------------------------------- scoring


def test_score_counts_each_rule_once() -> None:
    scorer = RiskScorer(Config())
    findings = [
        Finding(rule=FindingRule.DUPLICATE_SSID, ssid="x", bssid="a", weight=25, explanation="dup"),
        Finding(rule=FindingRule.DUPLICATE_SSID, ssid="x", bssid="b", weight=25, explanation="dup"),
    ]
    assert scorer.score_for(findings) == 25  # not 50


def test_score_is_clamped_to_100() -> None:
    scorer = RiskScorer(Config())
    findings = [
        Finding(rule=rule, ssid="x", bssid="a", weight=weight, explanation="x")
        for rule, weight in [
            (FindingRule.DUPLICATE_SSID, 60),
            (FindingRule.UNKNOWN_BSSID, 60),
        ]
    ]
    assert scorer.score_for(findings) == 100


def test_zero_weight_findings_add_nothing() -> None:
    scorer = RiskScorer(Config())
    findings = [Finding(rule=FindingRule.NEW_ACCESS_POINT, ssid="x", bssid="a", weight=0, explanation="x")]
    assert scorer.score_for(findings) == 0


def test_full_assessment_explains_every_point() -> None:
    engine = DetectionEngine(Config(), persistence_scans=2)
    engine.evaluate(risky_context())
    report = engine.evaluate(risky_context())

    scorer = RiskScorer(Config())
    assessments = scorer.assess_grouped(report.groups)
    assert assessments
    worst = assessments[0]
    # 30 downgrade + 25 duplicate + 20 unknown + 10 new + 10 persistence + 5 signal = 100
    assert worst.score == 100
    assert worst.severity is Severity.CRITICAL
    assert len(worst.reasons) == 6
    assert worst.evidence.startswith("security_downgrade:")
    assert dict(worst.rule_scores)["security_downgrade"] == 30
    assert all(reason for reason in worst.reasons)


def test_assessment_severity_uses_configured_thresholds() -> None:
    scorer = RiskScorer(Config(suspicious_threshold=10, high_threshold=20, critical_threshold=30))
    findings = [Finding(rule=FindingRule.DUPLICATE_SSID, ssid="x", bssid="a", weight=25, explanation="dup")]
    assessment = scorer.assess(("x", "a"), findings)
    assert assessment.score == 25
    assert assessment.severity is Severity.HIGH


def test_clean_identity_is_reported_as_clean() -> None:
    scorer = RiskScorer(Config())
    assessment = scorer.assess(("x", None), [])
    assert assessment.is_clean
    assert assessment.score == 0
    assert assessment.severity is Severity.LOW
    assert assessment.evidence == "no indicators matched"


def test_assessment_serialises_safely() -> None:
    scorer = RiskScorer(Config())
    findings = [Finding(rule=FindingRule.PERSISTENCE, ssid="x", bssid="a", weight=10, explanation="kept")]
    payload = scorer.assess(("x", "a"), findings).to_dict()
    assert payload["score"] == 10
    assert payload["severity"] == "low"
    assert isinstance(payload["reasons"], list)
    assert isinstance(payload["evaluated_at"], str)
