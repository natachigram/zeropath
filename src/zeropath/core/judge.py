"""Skeptical judge engine for candidate findings."""

from __future__ import annotations

from zeropath.core.evidence import missing_evidence
from zeropath.core.schemas import CandidateFinding, JudgeResult, RejectionCheck
from zeropath.core.storage import Storage


FUND_IMPACT_TYPES = {
    "direct_theft",
    "unauthorized_withdrawal",
    "unauthorized_mint",
    "bad_debt",
    "accounting_corruption",
    "permanent_freeze",
    "liquidation_theft",
    "bridge_double_mint",
    "oracle_manipulation",
}


def judge_candidate(candidate: CandidateFinding, storage: Storage | None = None) -> JudgeResult:
    """Run evidence-gated report readiness checks."""

    evidence = candidate.evidence
    blocking: list[str] = []
    next_steps: list[str] = []

    funds_at_risk = candidate.impact.funds_at_risk
    if not funds_at_risk:
        blocking.append("No meaningful funds at risk were demonstrated.")

    attacker_realistic = bool(candidate.attacker_model) and "trusted admin only" not in candidate.attacker_model.lower()
    if not attacker_realistic:
        blocking.append("No realistic untrusted attacker model is present.")

    has_sequence = bool(candidate.transaction_sequence) and evidence.attacker_path_present
    if not has_sequence:
        blocking.append("No evidenced attacker transaction path is present.")

    state_reachable = bool(candidate.required_state) and evidence.state_preconditions_present
    if not state_reachable:
        blocking.append("Reachable state preconditions are missing or unevidenced.")

    root_cause_present = bool(candidate.root_cause_locations) and evidence.root_cause_lines_present
    if not root_cause_present:
        blocking.append("Root cause source lines are missing or unevidenced.")

    live_config_reachable = evidence.chain_id is not None or evidence.fork_block is not None
    if not live_config_reachable:
        next_steps.append("Check live/fork configuration or document why local-only proof is sufficient.")

    known_issue = (candidate.known_issue_risk or "").lower() == "high"
    if known_issue:
        blocking.append("Known issue risk is high.")

    duplicate_risk = candidate.duplicate_risk or "unknown"
    if duplicate_risk.lower() == "high" and not evidence.poc_path:
        blocking.append("Duplicate risk is high and evidence is weak.")

    proof_passed = evidence.forge_result == "passed" or evidence.invariant_test_result == "passed"
    proof_present = bool(evidence.poc_path or evidence.trace_path or proof_passed)
    if not proof_present:
        next_steps.append("Generate a PoC, trace, invariant test, or executable proof plan.")
    if proof_present and not proof_passed:
        next_steps.append("Run the proof artifact and record the result.")

    impact_measured = candidate.impact.measured or evidence.profit_measured
    if funds_at_risk and not impact_measured:
        next_steps.append("Measure impact or explain the concrete funds-at-risk bound.")

    for item in missing_evidence(evidence):
        step = f"Add evidence for {item}."
        if step not in next_steps:
            next_steps.append(step)

    severity = _severity(candidate, funds_at_risk, attacker_realistic, proof_passed, impact_measured)
    report_ready = (
        funds_at_risk
        and attacker_realistic
        and state_reachable
        and has_sequence
        and root_cause_present
        and live_config_reachable
        and not known_issue
        and not blocking
        and proof_passed
        and impact_measured
    )

    explanation = "Report ready." if report_ready else "Candidate needs more evidence or has blocking objections."
    result = JudgeResult(
        candidate_id=candidate.id,
        funds_at_risk=funds_at_risk,
        attacker_realistic=attacker_realistic,
        state_reachable=state_reachable,
        live_config_reachable=live_config_reachable,
        known_issue=known_issue,
        duplicate_risk=duplicate_risk,
        severity=severity,
        report_ready=report_ready,
        blocking_objections=blocking,
        required_next_steps=next_steps,
        explanation=explanation,
    )

    if storage is not None:
        storage.save_judge_result(result)
        candidate.rejection_checks = [
            RejectionCheck(check_name="judge", passed=not bool(blocking), reason="; ".join(blocking) or "no fatal blocking objections")
        ]
        if report_ready:
            candidate.status = "report_ready"
        elif _fatal_rejection(blocking):
            candidate.status = "rejected"
        else:
            candidate.status = "needs_evidence"
        storage.save_candidate(candidate)
    return result


def _severity(candidate: CandidateFinding, funds: bool, attacker: bool, proof: bool, measured: bool) -> str:
    impact_type = candidate.impact.impact_type
    if funds and attacker and proof and measured and impact_type in FUND_IMPACT_TYPES:
        if impact_type in {"direct_theft", "unauthorized_mint", "unauthorized_withdrawal", "bridge_double_mint", "bad_debt", "permanent_freeze"}:
            return "critical"
        return "high"
    if funds and attacker:
        return "high"
    if funds:
        return "medium"
    return "low"


def _fatal_rejection(blocking: list[str]) -> bool:
    fatal_fragments = (
        "No meaningful funds at risk",
        "No realistic untrusted attacker",
        "Known issue risk is high",
    )
    return any(any(fragment in item for fragment in fatal_fragments) for item in blocking)
