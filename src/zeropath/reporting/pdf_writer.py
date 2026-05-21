"""
PDF writer — Phase 9 (optional).

PDF generation has heavy dependencies (`reportlab`, or `weasyprint` for
HTML→PDF). Following the same pattern as Phase 5 fuzzers and Phase 8
GraphRAG, this writer detects whether a supported backend is available
and gracefully degrades when nothing is installed.

Supported backends (auto-detected in order):
  1. ``reportlab`` — Pure-Python, no native deps for the basic platypus
     layout. Recommended.
  2. ``weasyprint`` — HTML/CSS → PDF (renders the Phase 9 HTML output).
     Heavier, requires cairo/pango on the host.

When neither is installed the writer raises :class:`PdfBackendMissing`,
which the orchestrator catches and replaces with a Markdown fallback.
"""

from __future__ import annotations

import logging
from io import BytesIO
from pathlib import Path
from typing import Optional

from zeropath.reporting.models import AuditReport, Finding, SeverityTier

logger = logging.getLogger(__name__)


class PdfBackendMissing(RuntimeError):
    """Neither ``reportlab`` nor ``weasyprint`` is installed."""


class PdfReportWriter:
    """
    Produce a PDF from an :class:`AuditReport`.

    Parameters
    ----------
    backend : "auto" | "reportlab" | "weasyprint"
        Force a specific backend or let the writer pick the first available.
    """

    def __init__(self, *, backend: str = "auto") -> None:
        self.backend = self._pick_backend(backend)

    # ------------------------------------------------------------------

    @staticmethod
    def _pick_backend(preference: str) -> str:
        if preference != "auto":
            return preference
        try:
            import reportlab  # noqa: F401
            return "reportlab"
        except ImportError:
            pass
        try:
            import weasyprint  # noqa: F401
            return "weasyprint"
        except ImportError:
            pass
        return "none"

    @property
    def is_available(self) -> bool:
        return self.backend != "none"

    # ------------------------------------------------------------------

    def render_to_bytes(self, report: AuditReport) -> bytes:
        if not self.is_available:
            raise PdfBackendMissing(
                "no PDF backend installed — install reportlab (`pip install "
                "reportlab`) or weasyprint to enable PDF output"
            )
        if self.backend == "reportlab":
            return self._render_reportlab(report)
        if self.backend == "weasyprint":
            return self._render_weasyprint(report)
        raise PdfBackendMissing(f"unknown PDF backend: {self.backend}")

    def render_to_file(self, report: AuditReport, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.render_to_bytes(report))
        return target

    # ------------------------------------------------------------------
    # reportlab backend
    # ------------------------------------------------------------------

    def _render_reportlab(self, report: AuditReport) -> bytes:
        from reportlab.lib.pagesizes import letter  # type: ignore
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle  # type: ignore
        from reportlab.lib.units import inch  # type: ignore
        from reportlab.platypus import (  # type: ignore
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            PageBreak,
        )

        buf = BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=letter,
            leftMargin=0.75 * inch, rightMargin=0.75 * inch,
            topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        )
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name="FindingTitle", parent=styles["Heading2"], spaceBefore=18,
        ))
        styles.add(ParagraphStyle(
            name="Meta", parent=styles["Italic"], textColor="#555555",
            fontSize=9, spaceAfter=8,
        ))

        story = []
        story.append(Paragraph(report.title, styles["Title"]))
        story.append(Paragraph(
            f"Generated {report.generated_at} &middot; "
            f"ZeroPath v{report.generator_version}",
            styles["Meta"],
        ))
        story.append(Spacer(1, 0.2 * inch))

        # Executive summary
        story.append(Paragraph("Executive Summary", styles["Heading1"]))
        s = report.summary
        story.append(Paragraph(
            f"<b>Total findings:</b> {s.total_findings}", styles["BodyText"],
        ))
        for tier, count in s.by_severity.items():
            if count:
                story.append(Paragraph(
                    f"&bull; {tier.upper()}: {count}", styles["BodyText"],
                ))
        story.append(Paragraph(
            f"<b>Protocols analyzed:</b> {', '.join(s.protocols_analyzed) or 'none'}",
            styles["BodyText"],
        ))
        story.append(Spacer(1, 0.2 * inch))

        # Findings
        story.append(Paragraph("Findings", styles["Heading1"]))
        if not report.findings:
            story.append(Paragraph("<i>No findings surfaced.</i>", styles["BodyText"]))
        else:
            for f in report.findings:
                story.append(Paragraph(
                    f"[{f.finding_number}] {f.title}", styles["FindingTitle"],
                ))
                story.append(Paragraph(
                    f"<i>Severity: {f.severity.display} &middot; "
                    f"Class: {f.attack_class} &middot; "
                    f"Protocol: {f.protocol_name}</i>",
                    styles["Meta"],
                ))
                story.append(Paragraph("<b>Description</b>", styles["Heading4"]))
                story.append(Paragraph(self._for_pdf(f.description), styles["BodyText"]))
                story.append(Paragraph("<b>Impact</b>", styles["Heading4"]))
                story.append(Paragraph(self._for_pdf(f.impact), styles["BodyText"]))
                story.append(Paragraph("<b>Recommended Fix</b>", styles["Heading4"]))
                story.append(Paragraph(self._for_pdf(f.recommended_fix), styles["BodyText"]))
                if f.historical_precedent:
                    story.append(Paragraph("<b>Historical Precedent</b>", styles["Heading4"]))
                    for r in f.historical_precedent:
                        story.append(Paragraph(
                            f"&bull; {r.protocol} ({r.incident_date or 'n/a'}) — "
                            f"${r.loss_usd:,} loss",
                            styles["BodyText"],
                        ))
                story.append(Spacer(1, 0.15 * inch))

        doc.build(story)
        return buf.getvalue()

    # ------------------------------------------------------------------
    # weasyprint backend (delegates to the HTML writer)
    # ------------------------------------------------------------------

    def _render_weasyprint(self, report: AuditReport) -> bytes:
        import weasyprint  # type: ignore

        from zeropath.reporting.html_writer import HtmlReportWriter

        html_str = HtmlReportWriter().render(report)
        return weasyprint.HTML(string=html_str).write_pdf()

    # ------------------------------------------------------------------

    @staticmethod
    def _for_pdf(text: str) -> str:
        """Escape minimal HTML and preserve line breaks for ReportLab."""
        if not text:
            return "<i>(none)</i>"
        import html as _html
        return _html.escape(text).replace("\n", "<br/>")
