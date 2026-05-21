"""
Markdown writer — Phase 9.

Spec audit-report structure (phases.md, PHASE 9)::

    Executive Summary
      - Total findings: X critical, Y high, Z medium
      - Protocols analyzed: ...
      - Analysis depth: phases completed

    Findings
      [CRITICAL-001] Oracle Manipulation in LendingPool.borrow()
        - Description
        - Proof of Concept (transaction sequence)
        - Impact
        - Recommended Fix
        - Historical Precedent

    Appendix
      - Protocol Graph Summary
      - Invariants Checked
      - Simulation Results
"""

from __future__ import annotations

from typing import Iterable

from zeropath.reporting.models import (
    AuditReport,
    Finding,
    HistoricalPrecedentRef,
    ProofOfConcept,
    ReportAppendix,
    SeverityTier,
)


class MarkdownReportWriter:
    """Render an :class:`AuditReport` as Markdown."""

    def __init__(self, *, include_appendix: bool = True) -> None:
        self.include_appendix = include_appendix

    def render(self, report: AuditReport) -> str:
        parts: list[str] = []
        parts.append(self._header(report))
        parts.append(self._executive_summary(report))
        parts.append(self._findings_section(report.findings))
        if self.include_appendix:
            parts.append(self._appendix_section(report.appendix))
        return "\n\n".join(p for p in parts if p).rstrip() + "\n"

    # ------------------------------------------------------------------
    # Section builders
    # ------------------------------------------------------------------

    def _header(self, report: AuditReport) -> str:
        return (
            f"# {report.title}\n\n"
            f"_Generated: {report.generated_at}_  \n"
            f"_Generator: ZeroPath v{report.generator_version}_"
        )

    def _executive_summary(self, report: AuditReport) -> str:
        s = report.summary
        breakdown = ", ".join(
            f"{count} {tier}"
            for tier, count in s.by_severity.items()
            if count > 0
        ) or "0"
        lines = [
            "## Executive Summary",
            "",
            f"- **Total findings:** {s.total_findings} ({breakdown})",
            f"- **Protocols analyzed:** {', '.join(s.protocols_analyzed) or 'none'}",
            f"- **Phases completed:** {', '.join(str(p) for p in s.phases_completed) or 'n/a'}",
            f"- **Total profit at risk:** ${s.total_profit_at_risk_usd:,.0f}",
        ]
        if s.accuracy_summary:
            acc_overall = s.accuracy_summary.get("overall", {})
            if acc_overall:
                lines.append(
                    f"- **Prediction accuracy (overall):** "
                    f"{acc_overall.get('precision', 0) * 100:.1f}% precision "
                    f"on {acc_overall.get('total', 0)} predictions"
                )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def _findings_section(self, findings: list[Finding]) -> str:
        if not findings:
            return "## Findings\n\n_No findings surfaced in this run._"
        out = ["## Findings", ""]
        for f in findings:
            out.append(self._render_finding(f))
            out.append("")
        return "\n".join(out).rstrip()

    def _render_finding(self, f: Finding) -> str:
        header = f"### [{f.finding_number}] {f.title}"
        meta = [
            f"_Severity: **{f.severity.display}**_",
            f"_Attack class: `{f.attack_class}`_",
            f"_Protocol: `{f.protocol_name}`_",
            f"_Confidence: {f.confidence:.2f}_",
        ]
        body: list[str] = [header, " · ".join(meta), ""]

        body.append("**Description**")
        body.append("")
        body.append(f.description or "_No description provided._")
        body.append("")

        body.append("**Impact**")
        body.append("")
        body.append(f.impact or "_Impact not assessed._")
        body.append("")

        body.append("**Proof of Concept**")
        body.append("")
        body.append(self._render_poc(f.proof_of_concept))
        body.append("")

        body.append("**Recommended Fix**")
        body.append("")
        body.append(f.recommended_fix or "_No automated remediation suggestion._")
        body.append("")

        body.append("**Historical Precedent**")
        body.append("")
        body.append(self._render_precedents(f.historical_precedent))
        body.append("")

        if f.contrarian_objections:
            body.append("**Contrarian Review**")
            body.append("")
            for obj in f.contrarian_objections:
                body.append(f"- {obj}")
            body.append("")

        return "\n".join(body).rstrip()

    @staticmethod
    def _render_poc(poc: ProofOfConcept | None) -> str:
        if poc is None:
            return "_No proof-of-concept attached._"
        lines: list[str] = []
        lines.append(f"- **Sequence ID:** `{poc.sequence_id}`")
        if poc.fork_block:
            lines.append(f"- **Fork block:** {poc.fork_block}")
        lines.append(f"- **Fork URL env var:** `{poc.fork_url_env}`")
        if poc.calls_summary:
            lines.append("- **Call sequence:**")
            for step in poc.calls_summary:
                lines.append(f"  - {step}")
        if poc.foundry_test_path:
            lines.append("")
            lines.append(f"Reproduce with Foundry: `forge test --match-path {poc.foundry_test_path}`")
        if poc.foundry_test_code:
            lines.append("")
            lines.append("<details><summary>Foundry test source</summary>")
            lines.append("")
            lines.append("```solidity")
            lines.append(poc.foundry_test_code.rstrip())
            lines.append("```")
            lines.append("</details>")
        return "\n".join(lines)

    @staticmethod
    def _render_precedents(refs: list[HistoricalPrecedentRef]) -> str:
        if not refs:
            return "_No historical incidents matched this attack class._"
        lines: list[str] = []
        for r in refs:
            line = f"- **{r.protocol}**"
            if r.incident_date:
                line += f" ({r.incident_date})"
            if r.loss_usd:
                line += f" — ${r.loss_usd:,} loss"
            line += f" _[source: {r.source}]_"
            if r.source_url:
                line += f"  \n  {r.source_url}"
            lines.append(line)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Appendix
    # ------------------------------------------------------------------

    def _appendix_section(self, appendix: ReportAppendix) -> str:
        out = ["## Appendix", ""]
        out.append("### Protocol Graph Summary")
        out.append("")
        out.append(self._render_kv_dict(appendix.protocol_graph_summary))
        out.append("")

        out.append("### Invariants Checked")
        out.append("")
        if appendix.invariants_checked:
            for inv in appendix.invariants_checked:
                out.append(
                    f"- **{inv.get('type', 'unknown')}** "
                    f"(severity={inv.get('severity', 'unknown')}, "
                    f"confidence={inv.get('confidence', 0):.2f}) — "
                    f"{inv.get('description', '')[:120]}"
                )
        else:
            out.append("_No invariants recorded._")
        out.append("")

        out.append("### Simulation Results")
        out.append("")
        if appendix.simulation_results:
            for sim in appendix.simulation_results:
                out.append(
                    f"- Sequence `{sim.get('sequence_id', 'n/a')}` → "
                    f"outcome={sim.get('outcome', 'unknown')}, "
                    f"profit_wei={sim.get('profit_wei', 0):,}, "
                    f"gas_used={sim.get('gas_used', 0):,}"
                )
        else:
            out.append("_No simulation results captured._")

        if appendix.swarm_agent_breakdown:
            out.append("")
            out.append("### Swarm Agent Breakdown")
            out.append("")
            out.append(self._render_kv_dict(appendix.swarm_agent_breakdown))
        return "\n".join(out).rstrip()

    @staticmethod
    def _render_kv_dict(d: dict) -> str:
        if not d:
            return "_No data._"
        lines = []
        for k, v in d.items():
            lines.append(f"- **{k}:** {v}")
        return "\n".join(lines)
