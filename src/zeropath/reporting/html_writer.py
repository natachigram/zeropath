"""
HTML writer — Phase 9.

Stdlib-only HTML renderer for the same :class:`AuditReport`. Embeds minimal
inline CSS so the output is portable (single-file). No external templating
dependency — every section is built via small string helpers + ``html.escape``
to prevent injection from finding text.
"""

from __future__ import annotations

import html
from typing import Iterable

from zeropath.reporting.models import (
    AuditReport,
    Finding,
    HistoricalPrecedentRef,
    ProofOfConcept,
    SeverityTier,
)


_BASE_CSS = """
:root { --critical:#b71c1c; --high:#e65100; --medium:#fbc02d; --low:#388e3c; --info:#1976d2; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       margin: 2rem auto; max-width: 920px; line-height: 1.5; color: #222; }
h1 { margin-bottom: 0.2rem; }
h2 { border-bottom: 1px solid #ddd; padding-bottom: 0.25rem; margin-top: 2.5rem; }
h3.finding { margin-top: 2rem; padding: 0.5rem 0.75rem; border-left: 6px solid var(--medium);
             background: #fafafa; border-radius: 4px; }
h3.finding.critical { border-color: var(--critical); }
h3.finding.high { border-color: var(--high); }
h3.finding.low { border-color: var(--low); }
h3.finding.informational { border-color: var(--info); }
.tag { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 0.8em;
       background: #eee; margin-right: 6px; }
.tag.critical { background: var(--critical); color: white; }
.tag.high { background: var(--high); color: white; }
.tag.medium { background: var(--medium); color: black; }
.tag.low { background: var(--low); color: white; }
.tag.informational { background: var(--info); color: white; }
pre, code { background: #f4f4f4; padding: 2px 4px; border-radius: 3px;
            font-family: SFMono-Regular, Consolas, monospace; }
pre { padding: 1rem; overflow-x: auto; }
.metadata { color: #555; font-size: 0.9em; }
.summary-table { border-collapse: collapse; margin-top: 1rem; }
.summary-table th, .summary-table td { border: 1px solid #ddd; padding: 6px 12px; text-align: left; }
"""


class HtmlReportWriter:
    """Render an :class:`AuditReport` as a single self-contained HTML document."""

    def __init__(self, *, include_appendix: bool = True) -> None:
        self.include_appendix = include_appendix

    def render(self, report: AuditReport) -> str:
        body = "\n".join([
            self._exec_summary(report),
            self._findings_section(report.findings),
            self._appendix_section(report) if self.include_appendix else "",
        ])
        return (
            "<!DOCTYPE html>\n"
            '<html lang="en"><head>\n'
            '<meta charset="utf-8">\n'
            f"<title>{html.escape(report.title)}</title>\n"
            f"<style>{_BASE_CSS}</style>\n"
            "</head><body>\n"
            f"<h1>{html.escape(report.title)}</h1>\n"
            f'<div class="metadata">Generated: {html.escape(report.generated_at)} '
            f"&middot; ZeroPath v{html.escape(report.generator_version)}</div>\n"
            f"{body}\n"
            "</body></html>\n"
        )

    # ------------------------------------------------------------------

    def _exec_summary(self, report: AuditReport) -> str:
        s = report.summary
        rows = "".join(
            f"<tr><td>{html.escape(tier.upper())}</td><td>{count}</td></tr>"
            for tier, count in s.by_severity.items()
            if count > 0
        ) or "<tr><td colspan='2'>none</td></tr>"
        return (
            "<h2>Executive Summary</h2>\n"
            f"<p><strong>Total findings:</strong> {s.total_findings}</p>\n"
            f"<table class='summary-table'><tr><th>Severity</th><th>Count</th></tr>{rows}</table>\n"
            f"<p><strong>Protocols analyzed:</strong> {html.escape(', '.join(s.protocols_analyzed) or 'none')}</p>\n"
            f"<p><strong>Phases completed:</strong> {html.escape(', '.join(str(p) for p in s.phases_completed) or 'n/a')}</p>\n"
            f"<p><strong>Total profit at risk:</strong> ${s.total_profit_at_risk_usd:,.0f}</p>\n"
        )

    def _findings_section(self, findings: list[Finding]) -> str:
        if not findings:
            return "<h2>Findings</h2>\n<p><em>No findings surfaced in this run.</em></p>"
        parts = ["<h2>Findings</h2>"]
        for f in findings:
            parts.append(self._render_finding(f))
        return "\n".join(parts)

    def _render_finding(self, f: Finding) -> str:
        sev = f.severity.value
        sev_display = html.escape(f.severity.display)
        title = html.escape(f.title)
        return (
            f'<h3 class="finding {sev}">[{html.escape(f.finding_number)}] {title}</h3>\n'
            f'<div class="metadata">'
            f'<span class="tag {sev}">{sev_display}</span>'
            f'<span class="tag">attack: {html.escape(f.attack_class)}</span>'
            f'<span class="tag">protocol: {html.escape(f.protocol_name)}</span>'
            f'<span class="tag">confidence: {f.confidence:.2f}</span>'
            f"</div>\n"
            f"<h4>Description</h4><p>{self._paragraph(f.description)}</p>\n"
            f"<h4>Impact</h4><p>{self._paragraph(f.impact)}</p>\n"
            f"<h4>Proof of Concept</h4>{self._render_poc(f.proof_of_concept)}\n"
            f"<h4>Recommended Fix</h4><div>{self._paragraph(f.recommended_fix)}</div>\n"
            f"<h4>Historical Precedent</h4>{self._render_precedents(f.historical_precedent)}\n"
        )

    @staticmethod
    def _paragraph(text: str) -> str:
        if not text:
            return "<em>(none)</em>"
        return html.escape(text).replace("\n", "<br>")

    def _render_poc(self, poc: ProofOfConcept | None) -> str:
        if poc is None:
            return "<p><em>No proof-of-concept attached.</em></p>"
        lines = ["<ul>"]
        lines.append(f"<li><strong>Sequence ID:</strong> <code>{html.escape(poc.sequence_id)}</code></li>")
        if poc.fork_block:
            lines.append(f"<li><strong>Fork block:</strong> {poc.fork_block}</li>")
        lines.append(f"<li><strong>RPC env var:</strong> <code>{html.escape(poc.fork_url_env)}</code></li>")
        if poc.calls_summary:
            lines.append("<li><strong>Call sequence:</strong><ol>")
            for s in poc.calls_summary:
                lines.append(f"<li>{html.escape(s)}</li>")
            lines.append("</ol></li>")
        lines.append("</ul>")
        if poc.foundry_test_code:
            lines.append(
                f"<details><summary>Foundry test source</summary>"
                f"<pre><code>{html.escape(poc.foundry_test_code)}</code></pre></details>"
            )
        return "\n".join(lines)

    def _render_precedents(self, refs: list[HistoricalPrecedentRef]) -> str:
        if not refs:
            return "<p><em>No historical incidents matched this attack class.</em></p>"
        lines = ["<ul>"]
        for r in refs:
            line = f"<li><strong>{html.escape(r.protocol)}</strong>"
            if r.incident_date:
                line += f" ({html.escape(r.incident_date)})"
            if r.loss_usd:
                line += f" — ${r.loss_usd:,} loss"
            line += f" <em>[source: {html.escape(r.source)}]</em>"
            if r.source_url:
                line += f' <a href="{html.escape(r.source_url)}">link</a>'
            line += "</li>"
            lines.append(line)
        lines.append("</ul>")
        return "\n".join(lines)

    def _appendix_section(self, report: AuditReport) -> str:
        a = report.appendix
        return (
            "<h2>Appendix</h2>\n"
            f"<h3>Protocol Graph Summary</h3>{self._kv_table(a.protocol_graph_summary)}\n"
            f"<h3>Invariants Checked</h3>{self._invariants_block(a.invariants_checked)}\n"
            f"<h3>Simulation Results</h3>{self._simulations_block(a.simulation_results)}\n"
        )

    @staticmethod
    def _kv_table(d: dict) -> str:
        if not d:
            return "<p><em>No data.</em></p>"
        rows = "".join(
            f"<tr><td><strong>{html.escape(str(k))}</strong></td><td>{html.escape(str(v))}</td></tr>"
            for k, v in d.items()
        )
        return f"<table class='summary-table'>{rows}</table>"

    @staticmethod
    def _invariants_block(rows: list[dict]) -> str:
        if not rows:
            return "<p><em>No invariants recorded.</em></p>"
        items = "".join(
            f"<li><strong>{html.escape(str(r.get('type', 'unknown')))}</strong> "
            f"(severity={html.escape(str(r.get('severity', 'unknown')))}, "
            f"confidence={r.get('confidence', 0):.2f}) — "
            f"{html.escape(str(r.get('description', ''))[:160])}</li>"
            for r in rows
        )
        return f"<ul>{items}</ul>"

    @staticmethod
    def _simulations_block(rows: list[dict]) -> str:
        if not rows:
            return "<p><em>No simulation results captured.</em></p>"
        items = "".join(
            f"<li>Sequence <code>{html.escape(str(r.get('sequence_id', 'n/a')))}</code> → "
            f"outcome={html.escape(str(r.get('outcome', 'unknown')))}, "
            f"profit_wei={r.get('profit_wei', 0):,}, "
            f"gas_used={r.get('gas_used', 0):,}</li>"
            for r in rows
        )
        return f"<ul>{items}</ul>"
