"""Evidence scoring based on concrete checklist items."""

from __future__ import annotations

from zeropath.core.schemas import EvidenceBundle


EVIDENCE_CHECKS = (
    "root_cause_lines_present",
    "attacker_path_present",
    "state_preconditions_present",
    "known_issues_checked",
    "duplicate_risk_checked",
    "live_config_checked",
    "poc_path",
    "trace_path",
    "forge_result",
    "invariant_test_result",
    "chain_id",
    "profit_measured",
)


def evidence_score(evidence: EvidenceBundle) -> int:
    """Return a concrete evidence score from boolean/artifact checklist items."""

    score = 0
    if evidence.root_cause_lines_present:
        score += 1
    if evidence.attacker_path_present:
        score += 1
    if evidence.state_preconditions_present:
        score += 1
    if evidence.known_issues_checked:
        score += 1
    if evidence.duplicate_risk_checked:
        score += 1
    if evidence.live_config_checked:
        score += 1
    if evidence.poc_path:
        score += 1
    if evidence.trace_path:
        score += 1
    if evidence.forge_result == "passed":
        score += 2
    elif evidence.forge_result:
        score += 1
    if evidence.invariant_test_result == "passed":
        score += 2
    elif evidence.invariant_test_result:
        score += 1
    if evidence.chain_id is not None or evidence.fork_block is not None:
        score += 1
    if evidence.profit_measured:
        score += 2
    return score


def missing_evidence(evidence: EvidenceBundle) -> list[str]:
    """List the important evidence still missing for report readiness."""

    missing: list[str] = []
    if not evidence.root_cause_lines_present:
        missing.append("root cause lines")
    if not evidence.attacker_path_present:
        missing.append("attacker path")
    if not evidence.state_preconditions_present:
        missing.append("reachable state preconditions")
    if not evidence.known_issues_checked:
        missing.append("known issue check")
    if not evidence.duplicate_risk_checked:
        missing.append("duplicate risk check")
    if not evidence.poc_path:
        missing.append("PoC artifact")
    if evidence.forge_result != "passed" and evidence.invariant_test_result != "passed":
        missing.append("passing proof result")
    if (
        evidence.chain_id is None
        and evidence.fork_block is None
        and not evidence.live_config_checked
    ):
        missing.append("live/fork configuration check")
    if not evidence.profit_measured:
        missing.append("measured impact/profit")
    return missing
