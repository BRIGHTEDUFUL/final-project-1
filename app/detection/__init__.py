"""Detection rules that compare observations against trusted baselines.

Findings are evidence-based and never assert malicious intent: legitimate
mesh and enterprise deployments broadcast one name from many radios.
"""

from __future__ import annotations

from app.detection.engine import DetectionEngine, DetectionReport
from app.detection.findings import (
    DetectionContext,
    Finding,
    FindingRule,
    IdentityKey,
    group_findings,
)
from app.detection.rules import (
    SUSPICIOUS_SIGNAL_THRESHOLD,
    all_rules,
    duplicate_ssid_rule,
    new_access_point_rule,
    security_downgrade_rule,
    suspicious_signal_rule,
    unknown_bssid_rule,
)

__all__ = [
    "SUSPICIOUS_SIGNAL_THRESHOLD",
    "DetectionContext",
    "DetectionEngine",
    "DetectionReport",
    "Finding",
    "FindingRule",
    "IdentityKey",
    "all_rules",
    "duplicate_ssid_rule",
    "group_findings",
    "new_access_point_rule",
    "security_downgrade_rule",
    "suspicious_signal_rule",
    "unknown_bssid_rule",
]
