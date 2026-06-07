from zeropath.core.judge import judge_candidate
from zeropath.core.schemas import CandidateFinding, EvidenceBundle, Impact, SourceLocation


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
            poc_path=".zeropath/artifacts/pocs/ZP_003.t.sol",
            forge_result="passed",
            chain_id=1,
            profit_measured=True,
        ),
    )

    result = judge_candidate(candidate)

    assert result.report_ready is True
    assert result.severity == "critical"
