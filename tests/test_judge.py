from pathlib import Path

from zeropath.core.evidence import evidence_score, missing_evidence
from zeropath.core.judge import judge_candidate
from zeropath.core.schemas import (
    CandidateFinding,
    EvidenceBundle,
    Impact,
    ProjectConfig,
    RejectionCheck,
    SourceLocation,
)
from zeropath.core.storage import Storage

REPO = Path(__file__).resolve().parents[1]
VULNERABLE_SRC = (REPO / "examples" / "erc4626_inflation_fixture" / "src" / "VulnerableVault.sol").read_text()
PROTECTED_SRC = (REPO / "examples" / "erc4626_protected_fixture" / "src" / "ProtectedVault.sol").read_text()


def _inflation_candidate(*, forge_result: str | None, vault_file: str, profit: bool = True) -> CandidateFinding:
    """A fully-evidenced ERC4626 inflation candidate, parameterised by proof state."""

    return CandidateFinding(
        id="ZP-INF",
        project_id="demo",
        title="Vault share accounting may be inflation-sensitive",
        bug_class="erc4626_share_inflation",
        attacker_model="Untrusted depositor able to donate assets.",
        affected_contracts=["VulnerableVault"],
        transaction_sequence=["attacker donates", "victim deposits", "attacker redeems"],
        required_state=["vault has low share supply"],
        root_cause_locations=[SourceLocation(file=vault_file, contract="VulnerableVault", function="totalAssets", line_start=56)],
        impact=Impact(
            impact_type="direct_theft",
            funds_at_risk=True,
            measured=profit,
            amount="1000 ether" if profit else None,
            explanation="Attacker profit measured." if profit else "",
        ),
        evidence=EvidenceBundle(
            root_cause_lines_present=True,
            attacker_path_present=True,
            state_preconditions_present=True,
            known_issues_checked=True,
            duplicate_risk_checked=True,
            live_config_checked=True,
            poc_path=".zeropath/artifacts/pocs/ZP_INF.t.sol",
            forge_result=forge_result,
            profit_measured=profit,
        ),
        known_issue_risk="low",
        duplicate_risk="medium",
    )


def _storage_with_source(tmp_path: Path, rel: str, source: str) -> Storage:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    return storage


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


def test_judge_blocks_inflation_candidate_before_proof(tmp_path):
    # Test 6: no passing proof yet -> not report-ready, and the judge asks for one.
    storage = _storage_with_source(tmp_path, "src/VulnerableVault.sol", VULNERABLE_SRC)
    candidate = _inflation_candidate(forge_result=None, vault_file="src/VulnerableVault.sol")
    candidate.evidence.poc_path = None

    result = judge_candidate(candidate, storage)

    assert result.report_ready is False
    assert any("proof" in step.lower() for step in result.required_next_steps)


def test_judge_marks_proven_inflation_candidate_reportable(tmp_path):
    # Test 7: a passing proof + measured impact on the vulnerable vault is
    # report-ready, and the anti-condition scan does not false-positive on it.
    storage = _storage_with_source(tmp_path, "src/VulnerableVault.sol", VULNERABLE_SRC)
    candidate = _inflation_candidate(forge_result="passed", vault_file="src/VulnerableVault.sol")

    result = judge_candidate(candidate, storage)

    assert result.report_ready is True
    assert result.severity == "critical"
    assert not any("anti-condition" in item.lower() for item in result.blocking_objections)


def test_judge_blocks_protected_vault_via_anti_condition(tmp_path):
    # Test 10: a protected vault (virtual shares + internal accounting) whose
    # proof did not pass is downgraded by the heuristic anti-condition detector.
    storage = _storage_with_source(tmp_path, "src/ProtectedVault.sol", PROTECTED_SRC)
    candidate = _inflation_candidate(forge_result="failed", vault_file="src/ProtectedVault.sol", profit=False)

    result = judge_candidate(candidate, storage)

    assert result.report_ready is False
    anti = [item for item in result.blocking_objections if "anti-condition" in item.lower()]
    assert anti, result.blocking_objections
    assert any("virtual_shares" in item or "internal_accounting" in item for item in anti)
    # The recorded rejection check documents the heuristic for the report.
    assert any(c.check_name == "anti_conditions" and not c.passed for c in candidate.rejection_checks)


def test_judge_passing_proof_overrides_anti_condition_heuristic(tmp_path):
    # Evidence beats heuristic: if the PoC actually passed and measured profit on
    # a "protected" vault, the guard is treated as a false positive, not a blocker.
    storage = _storage_with_source(tmp_path, "src/ProtectedVault.sol", PROTECTED_SRC)
    candidate = _inflation_candidate(forge_result="passed", vault_file="src/ProtectedVault.sol")

    result = judge_candidate(candidate, storage)

    assert result.report_ready is True
    assert not any("anti-condition" in item.lower() for item in result.blocking_objections)
    assert any("false positive" in step.lower() for step in result.required_next_steps)


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
