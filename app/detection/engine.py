"""Detection engine: runs the rules and tracks cross-scan persistence.

The engine is the only stateful part of detection. It remembers how many
consecutive scans an identity has produced findings in, which powers the
persistence indicator, and it can be reset at any time (for example when
monitoring stops).
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

from app.core.config import Config
from app.detection.findings import (
    DetectionContext,
    Finding,
    FindingRule,
    IdentityKey,
    group_findings,
)
from app.detection.rules import all_rules
from app.models import utcnow

logger = logging.getLogger(__name__)

__all__ = ["DetectionEngine", "DetectionReport"]


class DetectionReport:
    """Findings from one evaluation plus persistence statistics."""

    __slots__ = ("findings", "groups", "persistence_counts")

    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings
        self.groups: dict[IdentityKey, list[Finding]] = group_findings(findings)
        self.persistence_counts: dict[IdentityKey, int] = {}

    def for_identity(self, identity: IdentityKey) -> list[Finding]:
        """Findings belonging to one identity."""
        return list(self.groups.get(identity, []))

    @property
    def identity_count(self) -> int:
        """Number of distinct identities with findings."""
        return len(self.groups)

    def __len__(self) -> int:
        return len(self.findings)

    def __iter__(self) -> Iterator[Finding]:
        return iter(self.findings)


class DetectionEngine:
    """Evaluates detection rules over one scan at a time.

    Parameters
    ----------
    config:
        Supplies risk weights and thresholds.
    persistence_scans:
        Consecutive scans an identity must keep producing findings before the
        persistence indicator is added.
    """

    def __init__(
        self,
        config: Config | None = None,
        *,
        persistence_scans: int = 3,
    ) -> None:
        if persistence_scans < 2:
            raise ValueError(f"persistence_scans must be >= 2, got {persistence_scans}")
        self._config = config or Config()
        self._persistence_scans = persistence_scans
        self._consecutive: dict[IdentityKey, int] = {}

    @property
    def config(self) -> Config:
        """Configuration in use (weights and thresholds)."""
        return self._config

    @property
    def persistence_counts(self) -> dict[IdentityKey, int]:
        """Current consecutive-finding counters per identity."""
        return dict(self._consecutive)

    def reset(self) -> None:
        """Forget all persistence state (for example on monitoring stop)."""
        self._consecutive.clear()
        logger.debug("detection engine persistence state reset")

    def with_config(self, config: Config) -> DetectionEngine:
        """Return a new engine using ``config``, preserving persistence state."""
        engine = DetectionEngine(config, persistence_scans=self._persistence_scans)
        engine._consecutive.update(self._consecutive)
        return engine

    def evaluate(self, context: DetectionContext) -> DetectionReport:
        """Run all rules against ``context`` and return the report.

        Side effect: persistence counters are updated for every identity that
        produced at least one finding, and cleared for identities that did not.
        """
        findings = all_rules(context, self._config)
        report = DetectionReport(findings)

        # Track persistence for identities that produced findings this scan.
        flagged = set(report.groups)
        for identity in list(self._consecutive):
            if identity not in flagged:
                del self._consecutive[identity]

        persistence_findings: list[Finding] = []
        for identity in flagged:
            count = self._consecutive.get(identity, 0) + 1
            self._consecutive[identity] = count
            report.persistence_counts[identity] = count
            if count >= self._persistence_scans:
                ssid, bssid = identity
                persistence_findings.append(
                    Finding(
                        rule=FindingRule.PERSISTENCE,
                        ssid=ssid,
                        bssid=bssid,
                        weight=self._config.risk_weights.persistence,
                        explanation=(
                            f"The same suspicious pattern for "
                            f"{ssid or '<hidden>'} [{bssid or 'unknown BSSID'}] was seen in "
                            f"{count} consecutive scans."
                        ),
                        evidence={
                            "ssid": ssid,
                            "bssid": bssid,
                            "consecutive_scans": count,
                            "threshold": self._persistence_scans,
                        },
                        occurred_at=(
                            context.observations[0].observed_at if context.observations else utcnow()
                        ),
                    )
                )

        if persistence_findings:
            findings.extend(persistence_findings)
            report = DetectionReport(findings)
            report.persistence_counts = dict(self._consecutive)

        logger.debug(
            "detection evaluated %d observations -> %d findings across %d identities",
            len(context.observations),
            len(report.findings),
            report.identity_count,
        )
        return report
