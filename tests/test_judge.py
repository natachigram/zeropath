from zeropath.core.evidence import evidence_score, missing_evidence
from zeropath.core.judge import judge_candidate
from zeropath.core.schemas import (
    CandidateFinding,
    EvidenceBundle,
    Impact,
    RejectionCheck,
    SourceLocation,
)


def test_judge_rejects_no_funds_at_risk_candidate():
    candidate = CandidateFinding(
        id="ZP-001",
        project_id="demo",
        title="Missing event",
        impact=Impact(impact_type="hygiene", funds_at_risk=False, explanation="No funds"),
    )

    result = judge_candidate(candidate)

    assert result.report_ready is False
    assert any("No meaningful funds" in item for item in result.blocking_objections)


def test_judge_rejects_no_attacker_path_candidate():
    candidate = CandidateFinding(
        id="ZP-002",
        project_id="demo",
        title="Accounting issue",
        impact=Impact(impact_type="direct_theft", funds_at_risk=True, measured=True, explanation="Measured"),
        evidence=EvidenceBundle(root_cause_lines_present=True, state_preconditions_present=True),
        root_cause_locations=[SourceLocation(file="src/Vault.sol", line_start=10)],
        required_state=["victim deposit exists"],
    )

    result = judge_candidate(candidate)

    assert result.report_ready is False
    assert any("attacker transaction path" in item for item in result.blocking_objections)


def test_judge_marks_evidence_backed_candidate_reportable():
    candidate = CandidateFinding(
        id="ZP-003",
        project_id="demo",
        title="Direct theft",
        attacker_model="Untrusted depositor",
        transaction_sequence=["deposit", "victim deposit", "redeem"],
        required_state=["vault seeded"],
        root_cause_locations=[SourceLocation(file="src/Vault.sol", line_start=10)],
        impact=Impact(
            impact_type="direct_theft",
            funds_at_risk=True,
            measured=True,
            amount="1 ether",
            explanation="Attacker profit measured.",
        ),
        evidence=EvidenceBundle(
            root_cause_lines_present=True,
            attacker_path_present=True,
            state_preconditions_present=True,
            known_issues_checked=True,
            duplicate_risk_checked=True,
            live_config_checked=True,
            poc_path=".zeropath/artifacts/pocs/ZP_003.t.sol",
            forge_result="passed",
            chain_id=1,
            profit_measured=True,
        ),
    )

    result = judge_candidate(candidate)

    assert result.report_ready is True
    assert result.severity == "critical"


def test_judge_blocks_admin_only_paths_even_with_strong_artifacts():
    candidate = CandidateFinding(
        id="ZP-004",
        project_id="demo",
        title="Admin-only withdrawal",
        attacker_model="Trusted admin only",
        transaction_sequence=["owner withdraw"],
        required_state=["owner key signs transaction"],
        root_cause_locations=[SourceLocation(file="src/Vault.sol", line_start=10)],
        impact=Impact(
            impact_type="direct_theft",
            funds_at_risk=True,
            measured=True,
            amount="10 ether",
            explanation="Admin can withdraw funds.",
        ),
        evidence=EvidenceBundle(
            root_cause_lines_present=True,
            attacker_path_present=True,
            state_preconditions_present=True,
            known_issues_checked=True,
            duplicate_risk_checked=True,
            live_config_checked=True,
            poc_path=".zeropath/artifacts/pocs/ZP_004.t.sol",
            forge_result="passed",
            profit_measured=True,
        ),
    )

    result = judge_candidate(candidate)

    assert result.report_ready is False
    assert any("Admin-only" in item for item in result.blocking_objections)


def test_judge_requires_known_issue_and_duplicate_checks_for_report_readiness():
    candidate = CandidateFinding(
        id="ZP-005",
        project_id="demo",
        title="Direct theft without duplicate triage",
        attacker_model="Untrusted depositor",
        transaction_sequence=["deposit", "redeem"],
        required_state=["vault seeded"],
        root_cause_locations=[SourceLocation(file="src/Vault.sol", line_start=10)],
        impact=Impact(
            impact_type="direct_theft",
            funds_at_risk=True,
            measured=True,
            amount="1 ether",
            explanation="Attacker profit measured.",
        ),
        evidence=EvidenceBundle(
            root_cause_lines_present=True,
            attacker_path_present=True,
            state_preconditions_present=True,
            live_config_checked=True,
            poc_path=".zeropath/artifacts/pocs/ZP_005.t.sol",
            forge_result="passed",
            profit_measured=True,
        ),
    )

    result = judge_candidate(candidate)

    assert result.report_ready is False
    assert "known issue check" in missing_evidence(candidate.evidence)
    assert "duplicate risk check" in missing_evidence(candidate.evidence)
    assert any("known issues" in item for item in result.required_next_steps)
    assert any("duplicate risk" in item for item in result.required_next_steps)


def test_judge_uses_failed_rejection_checks_as_blockers():
    candidate = CandidateFinding(
        id="ZP-006",
        project_id="demo",
        title="Cap bypass claim",
        attacker_model="Untrusted borrower",
        transaction_sequence=["borrow"],
        required_state=["account near cap"],
        root_cause_locations=[SourceLocation(file="src/Lending.sol", line_start=42)],
        rejection_checks=[
            RejectionCheck(
                check_name="cap_bounds",
                passed=False,
                reason="Protocol cap limit blocks the requested borrow amount.",
            )
        ],
        impact=Impact(
            impact_type="bad_debt",
            funds_at_risk=True,
            measured=True,
            amount="100 ether",
            explanation="Borrow path would create bad debt.",
        ),
        evidence=EvidenceBundle(
            root_cause_lines_present=True,
            attacker_path_present=True,
            state_preconditions_present=True,
            known_issues_checked=True,
            duplicate_risk_checked=True,
            live_config_checked=True,
            poc_path=".zeropath/artifacts/pocs/ZP_006.t.sol",
            forge_result="passed",
            profit_measured=True,
        ),
    )

    result = judge_candidate(candidate)

    assert result.report_ready is False
    assert any("cap_bounds" in item for item in result.blocking_objections)


def test_evidence_score_counts_concrete_triage_checks():
    evidence = EvidenceBundle(
        root_cause_lines_present=True,
        attacker_path_present=True,
        state_preconditions_present=True,
        known_issues_checked=True,
        duplicate_risk_checked=True,
        live_config_checked=True,
        poc_path=".zeropath/artifacts/pocs/ZP_007.t.sol",
        forge_result="passed",
        profit_measured=True,
    )

    assert evidence_score(evidence) == 11
