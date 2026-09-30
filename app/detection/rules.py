"""Detection rules.

Each rule is a pure function from a :class:`DetectionContext` to findings.
Rules never mutate state and never claim certainty of malicious intent: they
report observable patterns with evidence.
"""

from __future__ import annotations

from app.core.config import Config, RiskWeights
from app.detection.findings import DetectionContext, Finding, FindingRule
from app.models import SecurityMode

__all__ = [
    "SUSPICIOUS_SIGNAL_THRESHOLD",
    "all_rules",
    "duplicate_ssid_rule",
    "new_access_point_rule",
    "security_downgrade_rule",
    "suspicious_signal_rule",
    "unknown_bssid_rule",
]

# Signal quality at or above which an unapproved radio is worth a note.
SUSPICIOUS_SIGNAL_THRESHOLD = 95


def duplicate_ssid_rule(context: DetectionContext, weights: RiskWeights) -> list[Finding]:
    """Unapproved BSSIDs sharing one SSID with another radio."""
    by_ssid: dict[str, set[str]] = {}
    for observation in context.observations:
        if observation.ssid is None or observation.bssid is None:
            continue
        by_ssid.setdefault(observation.ssid, set()).add(observation.bssid)

    findings: list[Finding] = []
    for ssid, bssids in by_ssid.items():
        if len(bssids) < 2:
            continue
        profile = context.trusted_for(ssid)
        unapproved = {b for b in bssids if not (profile.approves(b) if profile else False)}
        if not unapproved:
            continue
        approved_note = ""
        if profile and profile.knows_bssids:
            approved_note = f" {len(bssids) - len(unapproved)} of them are in the trusted profile."
        elif not profile:
            approved_note = " No trusted profile exists for this name yet."

        for bssid in sorted(unapproved):
            findings.append(
                Finding(
                    rule=FindingRule.DUPLICATE_SSID,
                    ssid=ssid,
                    bssid=bssid,
                    weight=weights.duplicate_ssid,
                    explanation=(
                        f"SSID '{ssid}' is broadcast by {len(bssids)} different access points; "
                        f"this radio ({bssid}) is not approved for it.{approved_note}"
                    ),
                    evidence={
                        "ssid": ssid,
                        "bssids": sorted(bssids),
                        "unapproved_bssids": sorted(unapproved),
                        "approved_bssids": list(profile.approved_bssids) if profile else [],
                        "note": "Multiple access points can legitimately share an SSID "
                        "(mesh/enterprise); verify before acting.",
                    },
                )
            )
    return findings


def unknown_bssid_rule(context: DetectionContext, weights: RiskWeights) -> list[Finding]:
    """A trusted name seen from a radio that is not in its approved set."""
    findings: list[Finding] = []
    for observation in context.observations:
        profile = context.trusted_for(observation.ssid)
        if profile is None or not profile.knows_bssids or observation.bssid is None:
            continue
        if profile.approves(observation.bssid):
            continue
        findings.append(
            Finding(
                rule=FindingRule.UNKNOWN_BSSID,
                ssid=observation.ssid,
                bssid=observation.bssid,
                weight=weights.unknown_bssid,
                explanation=(
                    f"Trusted network '{observation.ssid}' was seen from {observation.bssid}, "
                    f"which is not one of its {len(profile.approved_bssids)} approved BSSIDs."
                ),
                evidence={
                    "ssid": observation.ssid,
                    "observed_bssid": observation.bssid,
                    "approved_bssids": list(profile.approved_bssids),
                    "signal_strength": observation.signal_strength,
                    "observed_at": observation.observed_at.isoformat(),
                },
            )
        )
    return findings


def security_downgrade_rule(context: DetectionContext, weights: RiskWeights) -> list[Finding]:
    """Observed security weaker than the trusted profile expects."""
    findings: list[Finding] = []
    for observation in context.observations:
        profile = context.trusted_for(observation.ssid)
        if profile is None:
            continue
        expected = profile.expected_security_mode
        observed = observation.security_mode
        if expected is None or observed is None or observed is SecurityMode.UNKNOWN:
            continue
        if not observed.is_weaker_than(expected):
            continue
        findings.append(
            Finding(
                rule=FindingRule.SECURITY_DOWNGRADE,
                ssid=observation.ssid,
                bssid=observation.bssid,
                weight=weights.security_downgrade,
                explanation=(
                    f"Security for '{observation.ssid}' dropped from the expected "
                    f"{profile.expected_security} to the observed {observation.security}."
                ),
                evidence={
                    "ssid": observation.ssid,
                    "bssid": observation.bssid,
                    "expected_security": profile.expected_security,
                    "expected_mode": expected.value,
                    "observed_security": observation.security,
                    "observed_mode": observed.value,
                    "observed_at": observation.observed_at.isoformat(),
                },
            )
        )
    return findings


def new_access_point_rule(context: DetectionContext, weights: RiskWeights) -> list[Finding]:
    """A radio never observed before (suppressed when there is no history)."""
    if not context.history_available:
        return []

    findings: list[Finding] = []
    seen: set[str] = set()
    for observation in context.observations:
        bssid = observation.bssid
        if bssid is None or bssid in seen or bssid in context.known_bssids:
            continue
        seen.add(bssid)
        profile = context.trusted_for(observation.ssid)
        approved = profile.approves(bssid) if profile else False
        findings.append(
            Finding(
                rule=FindingRule.NEW_ACCESS_POINT,
                ssid=observation.ssid,
                bssid=bssid,
                weight=weights.new_access_point,
                explanation=f"Access point {bssid} has not been seen before in the recorded history.",
                evidence={
                    "ssid": observation.ssid,
                    "bssid": bssid,
                    "approved": approved,
                    "known_history_size": len(context.known_bssids),
                },
            )
        )
    return findings


def suspicious_signal_rule(context: DetectionContext, weights: RiskWeights) -> list[Finding]:
    """An unapproved radio with an unusually strong signal.

    Two heuristics are used: out-signalling the adapter's own connection
    (typical of a deliberately close rogue radio) and near-maximum signal
    quality from a radio that is neither connected nor approved.
    """
    findings: list[Finding] = []
    for observation in context.observations:
        if observation.bssid is None or observation.signal_strength is None:
            continue
        if context.is_approved(observation):
            continue

        reason: str | None = None
        if (
            context.connected_signal is not None
            and observation.bssid != context.connected_bssid
            and observation.signal_strength > context.connected_signal
        ):
            reason = (
                f"signal {observation.signal_strength}% exceeds the connected network's "
                f"{context.connected_signal}%"
            )
        elif observation.signal_strength >= SUSPICIOUS_SIGNAL_THRESHOLD and observation.bssid not in (
            context.known_bssids
        ):
            reason = f"signal {observation.signal_strength}% from a radio with no prior history"

        if reason is None:
            continue
        findings.append(
            Finding(
                rule=FindingRule.SUSPICIOUS_SIGNAL,
                ssid=observation.ssid,
                bssid=observation.bssid,
                weight=weights.suspicious_signal,
                explanation=f"Unapproved radio {observation.bssid} reports an unusually strong signal: {reason}.",
                evidence={
                    "ssid": observation.ssid,
                    "bssid": observation.bssid,
                    "signal_strength": observation.signal_strength,
                    "connected_signal": context.connected_signal,
                    "connected_bssid": context.connected_bssid,
                },
            )
        )
    return findings


def all_rules(context: DetectionContext, config: Config) -> list[Finding]:
    """Run every rule and return the combined findings, in stable order."""
    weights = config.risk_weights
    findings: list[Finding] = []
    findings.extend(duplicate_ssid_rule(context, weights))
    findings.extend(unknown_bssid_rule(context, weights))
    findings.extend(security_downgrade_rule(context, weights))
    findings.extend(new_access_point_rule(context, weights))
    findings.extend(suspicious_signal_rule(context, weights))
    return findings
