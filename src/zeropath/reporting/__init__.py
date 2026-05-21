"""
Phase 9: Audit Report Generator + CI/CD Integration.

Turns the JSON outputs of Phases 1-8 into a human-readable audit report and
ships CI/CD assets so security checks land inside the developer's normal
workflow.

Public API::

    from zeropath.reporting import AuditReportGenerator, ReportFormat

    gen = AuditReportGenerator(knowledge=kg)
    report = gen.generate(
        validation_report=validation_report,
        swarm_report=swarm_report,
        sequence_report=seq_report,
        simulation_report=sim_report,
        invariant_report=inv_report,
    )
    paths = gen.write(report, output_dir="./out",
                       formats=(ReportFormat.MARKDOWN, ReportFormat.HTML))

    # CI/CD assets
    from zeropath.reporting import CICDAssetGenerator
    CICDAssetGenerator().write_all("./my-repo")
"""

from zeropath.reporting.audit_report import AuditReportGenerator
from zeropath.reporting.cicd import CICDAssetGenerator
from zeropath.reporting.finding_formatter import FindingFormatter
from zeropath.reporting.html_writer import HtmlReportWriter
from zeropath.reporting.markdown_writer import MarkdownReportWriter
from zeropath.reporting.models import (
    AuditReport,
    ExecutiveSummary,
    Finding,
    FindingStatus,
    HistoricalPrecedentRef,
    ProofOfConcept,
    ReportAppendix,
    ReportFormat,
    SeverityTier,
)
from zeropath.reporting.pdf_writer import PdfBackendMissing, PdfReportWriter
from zeropath.reporting.ranking import (
    assign_finding_numbers,
    count_by_severity,
    deduplicate,
    deduplicate_and_rank,
    rank,
)
from zeropath.reporting.remediation import RemediationEngine

__all__ = [
    # Orchestrator
    "AuditReportGenerator",
    # Components
    "FindingFormatter",
    "RemediationEngine",
    "MarkdownReportWriter",
    "HtmlReportWriter",
    "PdfReportWriter", "PdfBackendMissing",
    "CICDAssetGenerator",
    # Ranking helpers
    "deduplicate", "rank", "assign_finding_numbers",
    "deduplicate_and_rank", "count_by_severity",
    # Models
    "AuditReport", "Finding", "ExecutiveSummary", "ReportAppendix",
    "ProofOfConcept", "HistoricalPrecedentRef",
    "SeverityTier", "FindingStatus", "ReportFormat",
]
