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

    attacker_realistic = bool(candidate.attacker_model) and not _is_admin_only_path(candidate)
    if not attacker_realistic:
        blocking.append("No realistic untrusted attacker model is present.")
    if _is_admin_only_path(candidate):
        blocking.append("Admin-only or trusted-role path is not an untrusted exploit.")

    has_sequence = bool(candidate.transaction_sequence) and evidence.attacker_path_present
    if not has_sequence:
        blocking.append("No evidenced attacker transaction path is present.")

    state_reachable = bool(candidate.required_state) and evidence.state_preconditions_present
    if not state_reachable:
        blocking.append("Reachable state preconditions are missing or unevidenced.")

    root_cause_present = bool(candidate.root_cause_locations) and evidence.root_cause_lines_present
    if not root_cause_present:
        blocking.append("Root cause source lines are missing or unevidenced.")

    live_config_reachable = (
        evidence.live_config_checked
        or evidence.chain_id is not None
        or evidence.fork_block is not None
    )
    if not live_config_reachable:
        next_steps.append("Check live/fork configuration or document why local-only proof is sufficient.")

    if _is_hygiene_or_gas_only(candidate):
        blocking.append("Hygiene, style, event, or gas-only observations are not report-ready security findings.")
    if _is_dust_only(candidate):
        blocking.append("Only dust or immaterial value impact was demonstrated.")
    if _unsupported_token_condition(candidate):
        blocking.append("Unsupported token behavior is outside documented scope.")
    blocking.extend(_failed_rejection_checks(candidate))

    known_issue = (candidate.known_issue_risk or "").lower() == "high"
    if known_issue:
        blocking.append("Known issue risk is high.")
    known_issue_checked = evidence.known_issues_checked or (candidate.known_issue_risk or "").lower() in {
        "none",
        "low",
        "medium",
        "high",
    }
    if not known_issue_checked:
        next_steps.append("Check known issues and record known_issue_risk or evidence.known_issues_checked.")

    duplicate_risk = candidate.duplicate_risk or "unknown"
    if duplicate_risk.lower() == "high" and not evidence.poc_path:
        blocking.append("Duplicate risk is high and evidence is weak.")
    duplicate_checked = evidence.duplicate_risk_checked or duplicate_risk.lower() in {"none", "low", "medium", "high"}
    if not duplicate_checked:
        next_steps.append("Check duplicate risk and record duplicate_risk or evidence.duplicate_risk_checked.")

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
        and known_issue_checked
        and duplicate_checked
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
        "Admin-only or trusted-role path",
        "Hygiene, style, event, or gas-only",
        "Only dust or immaterial value",
        "Unsupported token behavior",
        "Rejection check",
        "Known issue risk is high",
    )
    return any(any(fragment in item for fragment in fatal_fragments) for item in blocking)


def _combined_text(candidate: CandidateFinding) -> str:
    checks = " ".join(f"{check.check_name} {check.reason}" for check in candidate.rejection_checks)
    return " ".join(
        [
            candidate.title,
            candidate.bug_class or "",
            candidate.attacker_model or "",
            candidate.notes,
            candidate.impact.impact_type,
            candidate.impact.explanation,
            candidate.impact.amount or "",
            " ".join(candidate.tags),
            " ".join(candidate.entrypoints),
            " ".join(candidate.required_state),
            " ".join(candidate.transaction_sequence),
            checks,
        ]
    ).lower()


def _is_admin_only_path(candidate: CandidateFinding) -> bool:
    attacker = (candidate.attacker_model or "").lower()
    if any(term in attacker for term in ("untrusted", "permissionless", "any user", "public caller")):
        return False
    text = _combined_text(candidate)
    admin_terms = (
        "trusted admin only",
        "admin-only",
        "owner only",
        "onlyowner",
        "only owner",
        "onlyadmin",
        "only admin",
        "multisig only",
        "requires owner",
        "requires admin",
        "role-gated",
        "trusted role",
    )
    return any(term in text for term in admin_terms)


def _is_hygiene_or_gas_only(candidate: CandidateFinding) -> bool:
    text = _combined_text(candidate)
    impact_type = candidate.impact.impact_type.lower()
    hygiene_types = {"hygiene", "missing_event", "gas", "style", "informational"}
    hygiene_terms = ("missing event", "style issue", "gas griefing", "gas optimization", "naming")
    return impact_type in hygiene_types or any(term in text for term in hygiene_terms)


def _is_dust_only(candidate: CandidateFinding) -> bool:
    text = _combined_text(candidate)
    amount = (candidate.impact.amount or "").lower()
    return (
        candidate.impact.impact_type.lower() in {"dust", "dust_loss", "rounding_dust"}
        or "dust" in candidate.tags
        or "dust" in amount
        or "1 wei" in amount
        or "few wei" in text
    )


def _unsupported_token_condition(candidate: CandidateFinding) -> bool:
    text = _combined_text(candidate)
    unsupported_terms = (
        "fee-on-transfer",
        "rebasing",
        "erc777",
        "weird token",
        "non-standard token",
        "blacklist token",
    )
    scoped_terms = ("in scope", "scope includes", "deployment uses", "supported token")
    return any(term in text for term in unsupported_terms) and not any(term in text for term in scoped_terms)


def _failed_rejection_checks(candidate: CandidateFinding) -> list[str]:
    fatal_terms = (
        "admin",
        "role",
        "pause",
        "cap",
        "limit",
        "spec allows",
        "intended behavior",
        "oracle bounds",
        "impossible",
        "not reachable",
        "trusted",
    )
    failures: list[str] = []
    for check in candidate.rejection_checks:
        if check.passed:
            continue
        text = f"{check.check_name} {check.reason}".lower()
        if any(term in text for term in fatal_terms):
            failures.append(f"Rejection check {check.check_name} failed: {check.reason}")
    return failures
