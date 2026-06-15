import pytest

from zeropath.core.errors import ReportNotReadyError
from zeropath.core.reports import export_report, render_report
from zeropath.core.schemas import (
    CandidateFinding,
    EvidenceBundle,
    Impact,
    JudgeResult,
    ProjectConfig,
    RejectionCheck,
    SourceLocation,
)
from zeropath.core.storage import Storage


def _candidate() -> CandidateFinding:
    return CandidateFinding(
        id="ZP-RPT-001",
        project_id="demo",
        title="Stale exchange rate enables share inflation",
        severity_guess="high",
        protocol_type="evm",
        bug_class="accounting_corruption",
        affected_invariant="shares must track assets",
        attacker_model="Untrusted depositor",
        entrypoints=["deposit(uint256,address)", "redeem(uint256,address,address)"],
        affected_contracts=["Vault"],
        root_cause_locations=[
            SourceLocation(
                file="src/Vault.sol",
                contract="Vault",
                function="deposit",
                line_start=10,
                line_end=12,
                description="exchange rate is read before assets are updated",
            )
        ],
        required_state=["vault has seeded assets", "attacker can donate before deposit"],
        transaction_sequence=["donate assets", "deposit at stale rate", "redeem excess shares"],
        impact=Impact(
            impact_type="direct_theft",
            funds_at_risk=True,
            measured=True,
            amount="1 ether",
            victim="vault depositors",
            explanation="The PoC shows the attacker exits with more assets than deposited.",
        ),
        evidence=EvidenceBundle(
            root_cause_lines_present=True,
            attacker_path_present=True,
            state_preconditions_present=True,
            known_issues_checked=True,
            duplicate_risk_checked=True,
            live_config_checked=True,
            poc_path=".zeropath/artifacts/pocs/ZP_RPT_001.t.sol",
            trace_path=".zeropath/artifacts/traces/ZP_RPT_001.txt",
            forge_result="passed",
            invariant_test_result="passed",
            fork_block=19_000_000,
            chain_id=1,
            profit_measured=True,
            notes=["manual duplicate search completed"],
        ),
        rejection_checks=[
            RejectionCheck(
                check_name="dust_filter",
                passed=True,
                reason="profit exceeds materiality threshold",
            )
        ],
        duplicate_risk="low",
        known_issue_risk="none",
        notes="A stale exchange-rate read lets the attacker mint excess shares.",
    )


def _judge(*, ready: bool = True) -> JudgeResult:
    return JudgeResult(
        candidate_id="ZP-RPT-001",
        funds_at_risk=True,
        attacker_realistic=True,
        state_reachable=ready,
        live_config_reachable=ready,
        known_issue=False,
        duplicate_risk="low",
        severity="critical" if ready else "high",
        report_ready=ready,
        blocking_objections=[] if ready else ["Reachable state preconditions are missing."],
        required_next_steps=[] if ready else ["Add evidence for reachable state preconditions."],
        explanation="Report ready." if ready else "Candidate needs more evidence.",
    )


def test_code4rena_report_is_evidence_first_and_links_sources():
    report = render_report(_candidate(), _judge(), report_format="code4rena", draft=False)

    assert report.startswith("# FINAL / REPORT READY: Stale exchange rate")
    assert report.index("## Evidence Gate") < report.index("## Links To Affected Code")
    assert "- Judge verdict: REPORT READY" in report
    assert "- Missing evidence: None" in report
    assert (
        "- [`src/Vault.sol:10-12`](src/Vault.sol#L10-L12) - `Vault.deposit`"
        " - exchange rate is read before assets are updated"
    ) in report
    assert "| Root cause source lines | yes | 1 location |" in report
    assert "## Judge Blockers\n\n- None" in report
    assert "## Judge Required Next Steps\n\n- None" in report


def test_sherlock_draft_uses_not_ready_language_and_platform_sections():
    report = render_report(_candidate(), _judge(ready=False), report_format="sherlock", draft=True)

    assert report.startswith("# DRAFT / NOT READY FOR SUBMISSION:")
    assert "DRAFT / NOT READY: this report has not passed the judge gate" in report
    assert "## Vulnerability Detail" in report
    assert "## Code Snippet" in report
    assert "## Links To Affected Code" not in report
    assert "- Judge verdict: NOT READY" in report
    assert "## Judge Blockers\n\n- Reachable state preconditions are missing." in report
    assert (
        "## Judge Required Next Steps\n\n- Add evidence for reachable state preconditions."
        in report
    )


def test_code4rena_report_includes_erc4626_inflation_mitigations():
    candidate = _candidate()
    candidate.bug_class = "erc4626_share_inflation"
    report = render_report(candidate, _judge(), report_format="code4rena", draft=False)

    mitigation = report.split("## Recommended Mitigation", 1)[1].split("##", 1)[0]
    assert "virtual shares" in mitigation
    assert "internal accounting" in mitigation
    assert "dead shares" in mitigation
    assert "first-deposit" in mitigation.lower()
    assert "donation-resistant" in mitigation


def test_generic_report_omits_erc4626_specific_mitigations():
    report = render_report(_candidate(), _judge(), report_format="code4rena", draft=False)
    mitigation = report.split("## Recommended Mitigation", 1)[1].split("##", 1)[0]
    assert "virtual shares" not in mitigation


def test_export_final_report_succeeds_after_judge_passes(tmp_path):
    # Test 9: with a report-ready judge result, the final export is written.
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    storage.save_candidate(_candidate())
    storage.save_judge_result(_judge(ready=True))

    path = export_report(storage, "ZP-RPT-001", report_format="code4rena", draft=False)
    report = path.read_text()

    assert path.name == "ZP-RPT-001_code4rena_final.md"
    assert "# FINAL / REPORT READY:" in report
    assert "## Proof Of Concept" in report


def test_export_report_preserves_final_gate_and_writes_marked_draft(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    storage.save_candidate(_candidate())
    storage.save_judge_result(_judge(ready=False))

    with pytest.raises(ReportNotReadyError, match="Reachable state preconditions"):
        export_report(storage, "ZP-RPT-001", report_format="cantina", draft=False)

    path = export_report(storage, "ZP-RPT-001", report_format="cantina", draft=True)
    report = path.read_text()

    assert path.name == "ZP-RPT-001_cantina_draft.md"
    assert "# DRAFT / NOT READY FOR SUBMISSION:" in report
    assert "## Affected Code" in report
    assert "## Evidence and Judge Checks" in report
