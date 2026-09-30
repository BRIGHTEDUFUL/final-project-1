"""Explainable risk scoring built from detection findings.

The score is a transparent sum: each distinct rule contributes its configured
weight exactly once (the largest contribution when a rule fires several times
for one identity), clamped to 0-100. Every point traces back to a finding
explanation, so an operator can always answer "why 65 and not 30?".
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime

from app.core.config import Config
from app.detection.findings import Finding, FindingRule, IdentityKey
from app.models import Severity, utcnow

__all__ = ["RiskAssessment", "RiskScorer"]

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """Score and explanation for one identity."""

    ssid: str | None
    bssid: str | None
    score: int
    severity: Severity
    reasons: tuple[str, ...] = ()
    rule_scores: tuple[tuple[str, int], ...] = ()
    findings: tuple[Finding, ...] = ()
    evaluated_at: datetime = field(default_factory=utcnow)

    @property
    def identity(self) -> IdentityKey:
        """Stable ``(ssid, bssid)`` key."""
        return (self.ssid, self.bssid)

    @property
    def is_clean(self) -> bool:
        """``True`` when no findings contributed to the score."""
        return not self.findings

    @property
    def evidence(self) -> str:
        """Human-readable explanation used in alerts and the UI."""
        return "; ".join(self.reasons) if self.reasons else "no indicators matched"

    def to_dict(self) -> dict[str, object]:
        """JSON-safe representation."""
        return {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "score": self.score,
            "severity": self.severity.value,
            "reasons": list(self.reasons),
            "rule_scores": [list(item) for item in self.rule_scores],
            "evaluated_at": self.evaluated_at.isoformat(),
        }


class RiskScorer:
    """Turns findings into a clamped, explainable score."""

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or Config()

    @property
    def config(self) -> Config:
        """Configuration supplying thresholds and weights."""
        return self._config

    def thresholds(self) -> tuple[int, int, int]:
        """Severity thresholds taken from configuration."""
        return (
            self._config.suspicious_threshold,
            self._config.high_threshold,
            self._config.critical_threshold,
        )

    def score_for(self, findings: Sequence[Finding]) -> int:
        """Sum distinct-rule contributions, clamped to 0-100."""
        best_by_rule: dict[FindingRule, int] = {}
        for finding in findings:
            if finding.weight <= 0:
                continue
            best_by_rule[finding.rule] = max(best_by_rule.get(finding.rule, 0), finding.weight)
        return max(0, min(100, sum(best_by_rule.values())))

    def assess(
        self,
        identity: IdentityKey,
        findings: Sequence[Finding],
        *,
        evaluated_at: datetime | None = None,
    ) -> RiskAssessment:
        """Build the assessment for one identity's findings."""
        ssid, bssid = identity
        ordered = sorted(findings, key=lambda f: (-f.weight, f.rule.value))
        score = self.score_for(ordered)

        best_by_rule: dict[FindingRule, Finding] = {}
        for finding in ordered:
            best_by_rule.setdefault(finding.rule, finding)

        reasons = tuple(f"{rule.value}: {finding.explanation}" for rule, finding in best_by_rule.items())
        rule_scores = tuple(
            (rule.value, finding.weight) for rule, finding in best_by_rule.items() if finding.weight > 0
        )

        assessment = RiskAssessment(
            ssid=ssid,
            bssid=bssid,
            score=score,
            severity=Severity.from_score(score, self.thresholds()),
            reasons=reasons,
            rule_scores=rule_scores,
            findings=tuple(ordered),
            evaluated_at=evaluated_at or utcnow(),
        )
        logger.debug(
            "risk score for %s [%s] = %d (%s)",
            ssid or "<hidden>",
            bssid or "unknown",
            assessment.score,
            assessment.severity.value,
        )
        return assessment

    def assess_grouped(
        self,
        groups: dict[IdentityKey, list[Finding]],
        *,
        evaluated_at: datetime | None = None,
    ) -> list[RiskAssessment]:
        """Assess every identity that produced findings, highest score first."""
        assessments = [
            self.assess(identity, findings, evaluated_at=evaluated_at)
            for identity, findings in groups.items()
        ]
        assessments.sort(key=lambda item: (-item.score, item.ssid or "", item.bssid or ""))
        return assessments
