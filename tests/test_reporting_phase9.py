"""
Phase 9 test suite — Audit Report Generator + CI/CD Integration.

Coverage:
  - models: SeverityTier ordering, Finding/AuditReport defaults
  - RemediationEngine: known classes + fallback
  - ranking: dedup, sort, finding-number assignment
  - FindingFormatter: ValidationResult + Hypothesis → Finding
  - MarkdownReportWriter: required sections + finding rendering
  - HtmlReportWriter: HTML escaping, structure
  - PdfReportWriter: backend detection + graceful skip
  - CICDAssetGenerator: GitHub Actions + pre-commit + readme
  - AuditReportGenerator: end-to-end + write() format multiplexing
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from zeropath.adversarial.models import (
    AttackClass,
    AttackHypothesis,
    AttackStep,
    ConditionType,
    HypothesisStatus,
    Precondition,
    ProfitMechanism,
    SwarmReport,
)
from zeropath.invariants.models import (
    DeFiProtocolType,
    Invariant,
    InvariantReport,
    InvariantSeverity,
    InvariantType,
    ProtocolPattern,
)
from zeropath.reporting import (
    AuditReport,
    AuditReportGenerator,
    CICDAssetGenerator,
    ExecutiveSummary,
    Finding,
    FindingFormatter,
    HtmlReportWriter,
    MarkdownReportWriter,
    PdfBackendMissing,
    PdfReportWriter,
    ProofOfConcept,
    RemediationEngine,
    ReportAppendix,
    ReportFormat,
    SeverityTier,
    assign_finding_numbers,
    count_by_severity,
    deduplicate,
    deduplicate_and_rank,
    rank,
)
from zeropath.sequencer.models import (
    AttackContext,
    GeneratedTest,
    ProfitEstimate,
    SequenceReport,
    TestFramework as _TF,
    TransactionSequence,
    TxCall,
)
from zeropath.simulator.models import (
    SimulationOutcome,
    SimulationReport,
    SimulationResult,
)
from zeropath.validation.models import (
    ProfitTier,
    RecommendedAction,
    SeverityScore,
    ValidationReport,
    ValidationResult,
)


# ===========================================================================
# Test fixtures
# ===========================================================================


def _mk_validation(
    *,
    valid: bool = True,
    profit_wei: int = 10 ** 18,
    profit_tier: ProfitTier = ProfitTier.CRITICAL,
    fingerprint: str = "fp-A",
    hypothesis_id: str | None = None,
    protocol_name: str = "TestProtocol",
    action: RecommendedAction = RecommendedAction.REPORT,
) -> ValidationResult:
    return ValidationResult(
        valid=valid,
        reason="all checks passed",
        confidence=0.85,
        severity=SeverityScore(
            profit_tier=profit_tier,
            requires_flash_loan=True,
            composite_score=0.7,
            mev_frontrunnable=True,
        ),
        recommended_action=action,
        hypothesis_id=hypothesis_id or str(uuid4()),
        sequence_id=str(uuid4()),
        simulation_id=str(uuid4()),
        protocol_name=protocol_name,
        fingerprint=fingerprint,
        profit_wei=profit_wei,
        profit_usd=profit_wei / 10 ** 18 * 3000,
    )


def _mk_hypothesis(
    attack_class: AttackClass = AttackClass.ORACLE_MANIPULATION,
    title: str = "Oracle manipulation in borrow()",
    contracts: list[str] | None = None,
) -> AttackHypothesis:
    return AttackHypothesis(
        invariant_id=str(uuid4()),
        invariant_description="test invariant",
        attack_class=attack_class,
        title=title,
        proposed_by="OracleManipulatorAgent",
        attack_narrative="Attacker manipulates Uniswap spot price.",
        contracts_involved=contracts or ["LendingPool"],
        functions_involved=["borrow"],
        exploit_steps=[
            AttackStep(step=1, action="flash loan", purpose="fund"),
            AttackStep(step=2, action="swap", purpose="skew oracle"),
            AttackStep(step=3, action="borrow against inflated collateral", purpose="extract"),
        ],
        preconditions=[
            Precondition(
                condition_type=ConditionType.ORACLE_READ_SINGLE_BLOCK,
                description="spot read in single block",
                is_met_by_protocol=True,
            ),
        ],
        profit_mechanism=ProfitMechanism(
            description="drain via inflated price", asset="WETH",
        ),
        confidence=0.85,
        status=HypothesisStatus.CONSENSUS,
    )


def _mk_sequence(*, hypothesis_id: str | None = None) -> TransactionSequence:
    return TransactionSequence(
        hypothesis_id=hypothesis_id or str(uuid4()),
        hypothesis_title="seq",
        attack_class="oracle_manipulation",
        calls=[
            TxCall(
                step=1, description="flash loan",
                target_address_expr="IPool(AAVE)",
                target_address="0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",
                function_signature="flashLoanSimple(address,address,uint256,bytes,uint16)",
            ),
            TxCall(
                step=2, description="swap to skew oracle",
                target_address_expr="IUniswapV2Pair(POOL)",
                target_address="0x000000000000000000000000000000000000aaaa",
                function_signature="swap(uint256,uint256,address,bytes)",
            ),
        ],
        context=AttackContext(chain="mainnet"),
        uses_flash_loan=True,
        block_number=18_500_000,
        foundry_test=GeneratedTest(
            framework=_TF.FOUNDRY,
            filename="TestOracleAttack.t.sol",
            code="// Test code goes here",
            run_command="forge test --match-path TestOracleAttack.t.sol",
        ),
    )


def _mk_simulation(*, sequence_id: str, profit_wei: int = 10 ** 18) -> SimulationResult:
    return SimulationResult(
        sequence_id=sequence_id,
        success=True,
        outcome=SimulationOutcome.PROFITABLE,
        profit_wei=profit_wei,
        gas_used=1_200_000,
        block_number=18_500_000,
    )


# ===========================================================================
# Models
# ===========================================================================


class TestSeverityTier:
    def test_rank_ordering(self):
        ranks = [t.rank for t in SeverityTier]
        assert ranks == sorted(ranks)

    def test_display(self):
        assert SeverityTier.CRITICAL.display == "CRITICAL"

    def test_critical_rank_lower_than_high(self):
        assert SeverityTier.CRITICAL.rank < SeverityTier.HIGH.rank


class TestAuditReportModel:
    def test_default_id_and_timestamp(self):
        r = AuditReport()
        assert r.id and r.generated_at

    def test_critical_filter(self):
        crit = Finding(title="c", severity=SeverityTier.CRITICAL)
        low = Finding(title="l", severity=SeverityTier.LOW)
        r = AuditReport(findings=[crit, low])
        assert r.critical_findings == [crit]

    def test_has_blocking_findings(self):
        r = AuditReport(findings=[Finding(title="x", severity=SeverityTier.HIGH)])
        assert r.has_blocking_findings is True
        r2 = AuditReport(findings=[Finding(title="x", severity=SeverityTier.LOW)])
        assert r2.has_blocking_findings is False


# ===========================================================================
# RemediationEngine
# ===========================================================================


class TestRemediationEngine:
    @pytest.mark.parametrize("cls", [
        AttackClass.ORACLE_MANIPULATION.value,
        AttackClass.REENTRANCY.value,
        AttackClass.ACCESS_CONTROL.value,
        AttackClass.FLASH_LOAN.value,
        AttackClass.GOVERNANCE.value,
        AttackClass.INTEGER_MATH.value,
        AttackClass.COMPOSABILITY.value,
        AttackClass.PRICE_MANIPULATION.value,
    ])
    def test_known_class_returns_specific_guidance(self, cls):
        eng = RemediationEngine()
        md = eng.suggest_markdown(cls)
        assert md  # non-empty
        assert eng.suggest_headline(cls) in md  # bold headline embedded
        assert "References" in md or "_References:_" in md

    def test_unknown_class_returns_fallback(self):
        md = RemediationEngine().suggest_markdown("totally_made_up")
        assert "auditor should map" in md or "weakness identified" in md

    def test_table_override(self):
        custom = {"x": {"headline": "use X", "details": "Y", "references": []}}
        eng = RemediationEngine(table=custom)
        assert "use X" in eng.suggest_markdown("x")


# ===========================================================================
# Ranking
# ===========================================================================


class TestRanking:
    def test_dedup_keeps_highest_confidence(self):
        f1 = Finding(title="A", fingerprint="X", protocol_name="P",
                     confidence=0.5, severity=SeverityTier.HIGH)
        f2 = Finding(title="B", fingerprint="X", protocol_name="P",
                     confidence=0.9, severity=SeverityTier.HIGH)
        out = deduplicate([f1, f2])
        assert len(out) == 1 and out[0].confidence == 0.9

    def test_dedup_keeps_separate_protocols(self):
        f1 = Finding(title="A", fingerprint="X", protocol_name="P1")
        f2 = Finding(title="B", fingerprint="X", protocol_name="P2")
        out = deduplicate([f1, f2])
        assert len(out) == 2

    def test_rank_by_severity_then_profit(self):
        low = Finding(title="low", severity=SeverityTier.LOW, profit_usd=1_000_000)
        critical = Finding(title="critical", severity=SeverityTier.CRITICAL, profit_usd=100)
        ranked = rank([low, critical])
        assert ranked[0].severity == SeverityTier.CRITICAL

    def test_assign_finding_numbers(self):
        findings = [
            Finding(title="A", severity=SeverityTier.CRITICAL),
            Finding(title="B", severity=SeverityTier.CRITICAL),
            Finding(title="C", severity=SeverityTier.HIGH),
        ]
        assign_finding_numbers(findings)
        nums = [f.finding_number for f in findings]
        assert nums == ["CRITICAL-001", "CRITICAL-002", "HIGH-001"]

    def test_deduplicate_and_rank_pipeline(self):
        f1 = Finding(title="A", fingerprint="X", protocol_name="P",
                     severity=SeverityTier.HIGH, confidence=0.5)
        f2 = Finding(title="A", fingerprint="X", protocol_name="P",
                     severity=SeverityTier.HIGH, confidence=0.9)
        f3 = Finding(title="B", fingerprint="Y", protocol_name="P",
                     severity=SeverityTier.CRITICAL)
        out = deduplicate_and_rank([f1, f2, f3])
        assert len(out) == 2
        assert out[0].finding_number == "CRITICAL-001"
        assert out[1].finding_number == "HIGH-001"

    def test_count_by_severity(self):
        counts = count_by_severity([
            Finding(title="x", severity=SeverityTier.CRITICAL),
            Finding(title="x", severity=SeverityTier.HIGH),
            Finding(title="x", severity=SeverityTier.HIGH),
        ])
        assert counts["critical"] == 1
        assert counts["high"] == 2
        assert counts["medium"] == 0


# ===========================================================================
# FindingFormatter
# ===========================================================================


class TestFindingFormatter:
    def test_formats_validation_to_finding(self):
        h = _mk_hypothesis()
        v = _mk_validation(hypothesis_id=h.id)
        s = _mk_sequence(hypothesis_id=h.id)
        sim = _mk_simulation(sequence_id=s.id)
        f = FindingFormatter().format_finding(
            validation=v, hypothesis=h, sequence=s, simulation=sim,
        )
        assert f.title == h.title
        assert f.severity == SeverityTier.CRITICAL
        assert f.attack_class == "oracle_manipulation"
        assert f.protocol_name == "TestProtocol"
        assert f.proof_of_concept is not None
        assert f.proof_of_concept.foundry_test_path == "TestOracleAttack.t.sol"
        assert f.contracts_involved == ["LendingPool"]

    def test_no_hypothesis_uses_metadata_for_title(self):
        v = _mk_validation()
        v.analysis_metadata = {"attack_class": "reentrancy"}
        f = FindingFormatter().format_finding(validation=v)
        assert f.attack_class == "reentrancy"
        assert "Reentrancy" in f.title

    def test_impact_text_includes_profit(self):
        h = _mk_hypothesis()
        v = _mk_validation(hypothesis_id=h.id, profit_wei=10 * 10 ** 18)
        f = FindingFormatter().format_finding(validation=v, hypothesis=h)
        assert "profit" in f.impact.lower()
        assert "frontrunnable" in f.impact.lower()


# ===========================================================================
# MarkdownReportWriter
# ===========================================================================


class TestMarkdownWriter:
    def _build_report(self):
        h = _mk_hypothesis()
        v = _mk_validation(hypothesis_id=h.id)
        s = _mk_sequence(hypothesis_id=h.id)
        sim = _mk_simulation(sequence_id=s.id)
        formatter = FindingFormatter()
        finding = formatter.format_finding(
            validation=v, hypothesis=h, sequence=s, simulation=sim,
        )
        finding.recommended_fix = RemediationEngine().suggest_markdown(
            finding.attack_class,
        )
        return AuditReport(
            title="T", findings=deduplicate_and_rank([finding]),
            summary=ExecutiveSummary(
                total_findings=1,
                by_severity={"critical": 1, "high": 0, "medium": 0, "low": 0, "informational": 0},
                protocols_analyzed=["TestProtocol"],
                phases_completed=[1, 2, 3, 4, 5, 6],
                total_profit_at_risk_usd=3000.0,
            ),
        )

    def test_contains_all_required_sections(self):
        report = self._build_report()
        md = MarkdownReportWriter().render(report)
        for header in (
            "# T",
            "## Executive Summary",
            "## Findings",
            "[CRITICAL-001]",
            "**Description**",
            "**Impact**",
            "**Proof of Concept**",
            "**Recommended Fix**",
            "**Historical Precedent**",
        ):
            assert header in md, f"missing '{header}'"

    def test_appendix_renders_when_enabled(self):
        report = self._build_report()
        md = MarkdownReportWriter(include_appendix=True).render(report)
        assert "## Appendix" in md

    def test_appendix_skipped_when_disabled(self):
        report = self._build_report()
        md = MarkdownReportWriter(include_appendix=False).render(report)
        assert "## Appendix" not in md

    def test_empty_findings_message(self):
        report = AuditReport(
            title="X",
            summary=ExecutiveSummary(by_severity={"critical": 0}),
        )
        md = MarkdownReportWriter().render(report)
        assert "No findings surfaced" in md


# ===========================================================================
# HtmlReportWriter
# ===========================================================================


class TestHtmlWriter:
    def test_basic_render(self):
        report = AuditReport(
            title="X",
            findings=[Finding(
                title="Finding A", severity=SeverityTier.HIGH,
                finding_number="HIGH-001", description="d", impact="i",
            )],
            summary=ExecutiveSummary(
                total_findings=1,
                by_severity={"high": 1, "critical": 0, "medium": 0, "low": 0, "informational": 0},
            ),
        )
        html = HtmlReportWriter().render(report)
        assert html.startswith("<!DOCTYPE html>")
        assert "Finding A" in html
        assert "[HIGH-001]" in html
        assert "class=\"finding high\"" in html or 'class="finding high"' in html

    def test_html_escaping_prevents_injection(self):
        report = AuditReport(
            title="<script>alert(1)</script>",
            findings=[Finding(
                title="bad <img src=x onerror=alert(1)>",
                severity=SeverityTier.LOW, finding_number="LOW-001",
            )],
            summary=ExecutiveSummary(),
        )
        html = HtmlReportWriter().render(report)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
        assert "<img src=x" not in html or "&lt;img src=x" in html


# ===========================================================================
# PdfReportWriter
# ===========================================================================


class TestPdfWriter:
    def test_detects_no_backend_gracefully(self, monkeypatch):
        # Force backend detection to find nothing
        monkeypatch.setattr(PdfReportWriter, "_pick_backend",
                            staticmethod(lambda pref: "none"))
        w = PdfReportWriter()
        assert w.is_available is False
        with pytest.raises(PdfBackendMissing):
            w.render_to_bytes(AuditReport())


# ===========================================================================
# CICDAssetGenerator
# ===========================================================================


class TestCICDGenerator:
    def test_render_github_actions_contains_expected_keys(self):
        gen = CICDAssetGenerator()
        yml = gen.render_github_actions()
        for marker in (
            "name: ZeroPath Security Audit",
            "on:",
            "pull_request:",
            "**/*.sol",
            "zeropath analyze",
            "ZEROPATH_BLOCK_ON_CRITICAL",
        ):
            assert marker in yml

    def test_render_pre_commit_includes_hook_id(self):
        yml = CICDAssetGenerator().render_pre_commit()
        assert "id: zeropath-quick-scan" in yml
        # File filter regex matches .sol / .vy
        assert "sol" in yml and "vy" in yml

    def test_write_all_creates_files(self, tmp_path):
        paths = CICDAssetGenerator().write_all(tmp_path)
        assert paths["github_actions"].exists()
        assert paths["pre_commit"].exists()
        assert paths["readme"].exists()
        assert "github" in str(paths["github_actions"])
        assert paths["pre_commit"].name == ".pre-commit-config.yaml"

    def test_pre_commit_appends_to_existing_file(self, tmp_path):
        existing = tmp_path / ".pre-commit-config.yaml"
        existing.write_text("repos:\n  - repo: other\n    hooks: []\n")
        CICDAssetGenerator().write_pre_commit(tmp_path)
        text = existing.read_text()
        assert "other" in text
        assert "zeropath-quick-scan" in text

    def test_pre_commit_idempotent_on_existing_hook(self, tmp_path):
        existing = tmp_path / ".pre-commit-config.yaml"
        existing.write_text(
            "repos:\n  - repo: local\n    hooks:\n      - id: zeropath-quick-scan\n",
        )
        CICDAssetGenerator().write_pre_commit(tmp_path)
        # No duplication: the marker still appears exactly once.
        assert existing.read_text().count("id: zeropath-quick-scan") == 1

    def test_block_on_critical_flag_renders(self):
        yml_t = CICDAssetGenerator(block_on_critical=True).render_github_actions()
        yml_f = CICDAssetGenerator(block_on_critical=False).render_github_actions()
        assert 'ZEROPATH_BLOCK_ON_CRITICAL: "true"' in yml_t
        assert 'ZEROPATH_BLOCK_ON_CRITICAL: "false"' in yml_f


# ===========================================================================
# AuditReportGenerator orchestrator
# ===========================================================================


def _build_end_to_end_inputs():
    h = _mk_hypothesis()
    v = _mk_validation(hypothesis_id=h.id)
    s = _mk_sequence(hypothesis_id=h.id)
    s.id = v.sequence_id  # link by sequence_id
    sim = _mk_simulation(sequence_id=s.id)

    swarm = SwarmReport(protocol_name="TestProtocol", hypotheses=[h])
    seq_report = SequenceReport(
        protocol_name="TestProtocol", sequences=[s],
        sequences_generated=1,
    )
    sim_report = SimulationReport(protocol_name="TestProtocol", results=[sim])
    val_report = ValidationReport(
        protocol_name="TestProtocol", results=[v],
    )
    inv_report = InvariantReport(
        protocol_name="TestProtocol",
        protocol_pattern=ProtocolPattern(
            protocol_types=[DeFiProtocolType.LENDING],
            has_oracle=True, borrow_functions=["borrow"],
        ),
        invariants=[
            Invariant(
                type=InvariantType.ORACLE_MANIPULATION,
                severity=InvariantSeverity.CRITICAL,
                description="single block oracle read",
                confidence=0.85,
            ),
        ],
    )
    return swarm, seq_report, sim_report, val_report, inv_report


class TestAuditReportGenerator:
    def test_end_to_end_generation(self):
        swarm, seqs, sims, val, inv = _build_end_to_end_inputs()
        gen = AuditReportGenerator(title="E2E")
        report = gen.generate(
            validation_report=val, swarm_report=swarm,
            sequence_report=seqs, simulation_report=sims,
            invariant_report=inv,
        )
        assert isinstance(report, AuditReport)
        assert len(report.findings) == 1
        f = report.findings[0]
        assert f.finding_number == "CRITICAL-001"
        # Remediation was injected
        assert f.recommended_fix
        # Summary populated
        assert report.summary.total_findings == 1
        assert report.summary.protocols_analyzed == ["TestProtocol"]
        # Appendix populated from invariants + simulations
        assert len(report.appendix.invariants_checked) == 1
        assert len(report.appendix.simulation_results) == 1

    def test_skips_invalid_validations(self):
        swarm, seqs, sims, val, inv = _build_end_to_end_inputs()
        val.results[0].valid = False
        report = AuditReportGenerator().generate(
            validation_report=val, swarm_report=swarm,
            sequence_report=seqs, simulation_report=sims,
            invariant_report=inv,
        )
        assert report.findings == []

    def test_write_emits_markdown_and_html(self, tmp_path):
        swarm, seqs, sims, val, inv = _build_end_to_end_inputs()
        gen = AuditReportGenerator()
        report = gen.generate(
            validation_report=val, swarm_report=swarm,
            sequence_report=seqs, simulation_report=sims,
            invariant_report=inv,
        )
        paths = gen.write(
            report, output_dir=tmp_path,
            formats=(ReportFormat.MARKDOWN, ReportFormat.HTML),
        )
        assert paths["markdown"].exists()
        assert paths["html"].exists()
        md = paths["markdown"].read_text()
        assert "CRITICAL-001" in md

    def test_pdf_falls_back_when_backend_missing(self, tmp_path, monkeypatch):
        swarm, seqs, sims, val, inv = _build_end_to_end_inputs()
        gen = AuditReportGenerator()
        report = gen.generate(
            validation_report=val, swarm_report=swarm,
            sequence_report=seqs, simulation_report=sims,
            invariant_report=inv,
        )
        # Force PdfReportWriter to think no backend is available
        monkeypatch.setattr(
            PdfReportWriter, "_pick_backend",
            staticmethod(lambda pref: "none"),
        )
        paths = gen.write(
            report, output_dir=tmp_path, formats=(ReportFormat.PDF,),
        )
        # The orchestrator writes a `.pdf.unavailable` placeholder
        assert "pdf" in paths
        assert paths["pdf"].suffix == ".unavailable"

    def test_metadata_populated(self):
        swarm, seqs, sims, val, inv = _build_end_to_end_inputs()
        gen = AuditReportGenerator()
        report = gen.generate(
            validation_report=val, swarm_report=swarm,
            sequence_report=seqs, simulation_report=sims,
            invariant_report=inv,
        )
        meta = report.analysis_metadata
        assert "elapsed_seconds" in meta
        assert meta["input_validations"] == 1
        assert meta["input_sequences"] == 1
        assert meta["input_simulations"] == 1
