"""
AuditReportGenerator — Phase 9 top-level coordinator.

Pipeline::

    [Phase 6 ValidationReport]
    [Phase 4 SequenceReport]       ─┐
    [Phase 5 SimulationReport]      │       FindingFormatter   ─►  raw Findings
    [Phase 3 SwarmReport]            ├──►
    [Phase 8 KnowledgeOrchestrator] ─┘                              │
                                                                    ▼
                                             RemediationEngine   ─►  fix text
                                                                    │
                                                                    ▼
                                          ranking.deduplicate_and_rank
                                                                    │
                                                                    ▼
                                                Builds ExecutiveSummary +
                                                ReportAppendix → AuditReport
                                                                    │
                            ┌───────────────────────────────────────┤
                            ▼                  ▼                    ▼
                  MarkdownReportWriter   HtmlReportWriter     PdfReportWriter
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Iterable, Optional

from zeropath.adversarial.models import AttackHypothesis, SwarmReport
from zeropath.invariants.models import Invariant, InvariantReport
from zeropath.knowledge.knowledge import KnowledgeGraphOrchestrator
from zeropath.reporting.finding_formatter import FindingFormatter
from zeropath.reporting.html_writer import HtmlReportWriter
from zeropath.reporting.markdown_writer import MarkdownReportWriter
from zeropath.reporting.models import (
    AuditReport,
    ExecutiveSummary,
    Finding,
    ReportAppendix,
    ReportFormat,
)
from zeropath.reporting.pdf_writer import PdfBackendMissing, PdfReportWriter
from zeropath.reporting.ranking import (
    count_by_severity,
    deduplicate_and_rank,
)
from zeropath.reporting.remediation import RemediationEngine
from zeropath.sequencer.models import SequenceReport, TransactionSequence
from zeropath.simulator.models import SimulationReport, SimulationResult
from zeropath.validation.models import ValidationReport, ValidationResult

logger = logging.getLogger(__name__)


class AuditReportGenerator:
    """
    Assemble a full :class:`AuditReport` from the upstream phase outputs.

    Parameters
    ----------
    title : str
        Title shown at the top of every output format.
    knowledge : KnowledgeGraphOrchestrator | None
        When provided, findings get historical-precedent links from the KG
        and the executive summary picks up accuracy metrics.
    remediation : RemediationEngine | None
        Override the default per-class remediation table.
    formatter : FindingFormatter | None
        Override for testing.
    """

    def __init__(
        self,
        *,
        title: str = "ZeroPath Audit Report",
        knowledge: Optional[KnowledgeGraphOrchestrator] = None,
        remediation: Optional[RemediationEngine] = None,
        formatter: Optional[FindingFormatter] = None,
    ) -> None:
        self.title = title
        self.knowledge = knowledge
        self.remediation = remediation or RemediationEngine()
        self.formatter = formatter or FindingFormatter(knowledge=knowledge)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        *,
        validation_report: ValidationReport,
        swarm_report: Optional[SwarmReport] = None,
        sequence_report: Optional[SequenceReport] = None,
        simulation_report: Optional[SimulationReport] = None,
        invariant_report: Optional[InvariantReport] = None,
        phases_completed: Iterable[int] = (1, 2, 3, 4, 5, 6),
    ) -> AuditReport:
        start = time.monotonic()

        hyp_by_id = {h.id: h for h in (swarm_report.hypotheses if swarm_report else [])}
        seq_by_id = {s.id: s for s in (sequence_report.sequences if sequence_report else [])}
        sim_by_seq = {r.sequence_id: r for r in (simulation_report.results if simulation_report else [])}

        # ---------- 1. Format ----------
        raw: list[Finding] = []
        for result in validation_report.results:
            if not result.valid:
                continue
            hypothesis = hyp_by_id.get(result.hypothesis_id)
            sequence = seq_by_id.get(result.sequence_id)
            simulation = sim_by_seq.get(result.sequence_id)
            finding = self.formatter.format_finding(
                validation=result,
                hypothesis=hypothesis,
                sequence=sequence,
                simulation=simulation,
            )
            finding.recommended_fix = self.remediation.suggest_markdown(finding.attack_class)
            raw.append(finding)

        # ---------- 2. Dedup + rank + number ----------
        findings = deduplicate_and_rank(raw)

        # ---------- 3. Summary + appendix ----------
        summary = self._build_summary(findings, validation_report, phases_completed)
        appendix = self._build_appendix(
            invariant_report=invariant_report,
            simulation_report=simulation_report,
            swarm_report=swarm_report,
        )

        report = AuditReport(
            title=self.title,
            summary=summary,
            findings=findings,
            appendix=appendix,
            analysis_metadata={
                "elapsed_seconds": round(time.monotonic() - start, 3),
                "input_validations": len(validation_report.results),
                "input_sequences": len(seq_by_id),
                "input_simulations": len(sim_by_seq),
                "knowledge_active": self.knowledge is not None,
            },
        )
        return report

    # ------------------------------------------------------------------
    # Rendering helpers
    # ------------------------------------------------------------------

    def render(self, report: AuditReport, *, fmt: ReportFormat) -> str | bytes:
        if fmt == ReportFormat.MARKDOWN:
            return MarkdownReportWriter().render(report)
        if fmt == ReportFormat.HTML:
            return HtmlReportWriter().render(report)
        if fmt == ReportFormat.PDF:
            writer = PdfReportWriter()
            if not writer.is_available:
                raise PdfBackendMissing(
                    "no PDF backend installed; install reportlab or weasyprint"
                )
            return writer.render_to_bytes(report)
        raise ValueError(f"unsupported format: {fmt}")

    def write(
        self,
        report: AuditReport,
        *,
        output_dir: str | Path,
        formats: Iterable[ReportFormat] = (ReportFormat.MARKDOWN, ReportFormat.HTML),
        basename: str = "audit-report",
    ) -> dict[str, Path]:
        """
        Render the requested formats to ``output_dir`` and return the
        mapping from format name → written path. PDF gracefully falls back
        to writing a `.pdf.unavailable` placeholder if no backend is
        installed.
        """
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        written: dict[str, Path] = {}
        for fmt in formats:
            ext = self._ext_for(fmt)
            path = out_dir / f"{basename}.{ext}"
            try:
                content = self.render(report, fmt=fmt)
            except PdfBackendMissing:
                placeholder = out_dir / f"{basename}.pdf.unavailable"
                placeholder.write_text(
                    "PDF backend not installed; install reportlab or weasyprint.\n"
                )
                written[fmt.value] = placeholder
                continue
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content, encoding="utf-8")
            written[fmt.value] = path
        return written

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _build_summary(
        self,
        findings: list[Finding],
        validation_report: ValidationReport,
        phases_completed: Iterable[int],
    ) -> ExecutiveSummary:
        by_severity = count_by_severity(findings)
        protocols = sorted({f.protocol_name for f in findings if f.protocol_name})
        if not protocols and validation_report.protocol_name:
            protocols = [validation_report.protocol_name]

        accuracy_summary: dict = {}
        if self.knowledge is not None:
            try:
                overall = self.knowledge.feedback.overall_accuracy()
                accuracy_summary["overall"] = {
                    "total": overall.total,
                    "validated": overall.validated,
                    "invalidated": overall.invalidated,
                    "precision": overall.precision,
                }
            except Exception:
                logger.debug("KG accuracy lookup failed", exc_info=True)

        return ExecutiveSummary(
            total_findings=len(findings),
            by_severity=by_severity,
            protocols_analyzed=protocols,
            phases_completed=list(phases_completed),
            total_profit_at_risk_usd=sum(f.profit_usd for f in findings),
            accuracy_summary=accuracy_summary,
        )

    @staticmethod
    def _build_appendix(
        *,
        invariant_report: Optional[InvariantReport],
        simulation_report: Optional[SimulationReport],
        swarm_report: Optional[SwarmReport],
    ) -> ReportAppendix:
        invariants_checked: list[dict] = []
        if invariant_report:
            for inv in invariant_report.invariants:
                invariants_checked.append({
                    "id": inv.id,
                    "type": inv.type.value,
                    "severity": inv.severity.value if hasattr(inv.severity, "value") else str(inv.severity),
                    "confidence": inv.confidence,
                    "description": inv.description,
                })

        sim_rows: list[dict] = []
        if simulation_report:
            for r in simulation_report.results:
                sim_rows.append({
                    "sequence_id": r.sequence_id,
                    "outcome": r.outcome.value,
                    "profit_wei": r.profit_wei,
                    "gas_used": r.gas_used,
                    "block_number": r.block_number,
                })

        graph_summary: dict = {}
        if invariant_report and invariant_report.protocol_pattern:
            pattern = invariant_report.protocol_pattern
            graph_summary = {
                "protocol_types": [t.value for t in (pattern.protocol_types or [])],
                "has_oracle": pattern.has_oracle,
                "has_flash_loan": pattern.has_flash_loan,
                "has_timelock": pattern.has_timelock,
                "has_reentrancy_guard": pattern.has_reentrancy_guard,
            }

        swarm_breakdown: dict = {}
        if swarm_report:
            swarm_breakdown = {
                "total_hypotheses": len(swarm_report.hypotheses),
                "agents": list((swarm_report.agent_stats or {}).keys()),
            }

        return ReportAppendix(
            protocol_graph_summary=graph_summary,
            invariants_checked=invariants_checked,
            simulation_results=sim_rows,
            swarm_agent_breakdown=swarm_breakdown,
        )

    @staticmethod
    def _ext_for(fmt: ReportFormat) -> str:
        return {
            ReportFormat.MARKDOWN: "md",
            ReportFormat.HTML: "html",
            ReportFormat.PDF: "pdf",
        }[fmt]
