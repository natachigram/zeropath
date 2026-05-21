"""
Pydantic models for Phase 9: Audit Report Generator.

Every report is built from typed records so the same data backs the
markdown, HTML, and PDF writers — no format-specific branching upstream.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SeverityTier(str, Enum):
    """Display tiers used for finding IDs and report sections."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def display(self) -> str:
        return self.value.upper()

    @property
    def rank(self) -> int:
        order = {
            SeverityTier.CRITICAL: 0,
            SeverityTier.HIGH: 1,
            SeverityTier.MEDIUM: 2,
            SeverityTier.LOW: 3,
            SeverityTier.INFORMATIONAL: 4,
        }
        return order[self]


class ReportFormat(str, Enum):
    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"


class FindingStatus(str, Enum):
    NEW = "new"
    """First time we've surfaced this issue."""

    REGRESSION = "regression"
    """Same fingerprint as a previously fixed finding."""

    PRE_EXISTING = "pre_existing"
    """Already known — shipped from the Phase 8 KG."""


# ---------------------------------------------------------------------------
# Core finding record
# ---------------------------------------------------------------------------


class ProofOfConcept(BaseModel):
    """Concrete reproduction artefact attached to a finding."""

    model_config = ConfigDict(populate_by_name=True)

    sequence_id: str = ""
    foundry_test_path: Optional[str] = None
    foundry_test_code: Optional[str] = None
    hardhat_script_path: Optional[str] = None
    hardhat_script_code: Optional[str] = None
    fork_block: Optional[int] = None
    fork_url_env: str = "ETH_RPC_URL"
    calls_summary: list[str] = Field(
        default_factory=list,
        description="One-line summary per TxCall, ordered.",
    )


class HistoricalPrecedentRef(BaseModel):
    """Lightweight link to a Phase 8 ExternalIncidentRecord."""

    model_config = ConfigDict(populate_by_name=True)

    incident_id: str
    protocol: str
    incident_date: Optional[str] = None
    loss_usd: int = 0
    source: str = "unknown"
    source_url: str = ""


class Finding(BaseModel):
    """
    One report row. Generated from a Phase 6 ValidationResult (+ optional
    Phase 8 KG enrichment) by :class:`FindingFormatter`.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    finding_number: str = Field(
        "",
        description="Display ID like 'CRITICAL-001'. Set by the orchestrator after ranking.",
    )

    title: str
    severity: SeverityTier = SeverityTier.MEDIUM
    attack_class: str = "unknown"
    status: FindingStatus = FindingStatus.NEW

    # Provenance back to upstream phases
    validation_result_id: str = ""
    hypothesis_id: str = ""
    sequence_id: str = ""
    simulation_id: str = ""
    fingerprint: str = ""

    protocol_name: str = "unknown"
    contracts_involved: list[str] = Field(default_factory=list)
    functions_involved: list[str] = Field(default_factory=list)

    # Spec required sections per finding
    description: str = ""
    impact: str = ""
    proof_of_concept: Optional[ProofOfConcept] = None
    recommended_fix: str = ""
    historical_precedent: list[HistoricalPrecedentRef] = Field(default_factory=list)

    # Severity / scoring detail
    profit_wei: int = 0
    profit_usd: float = 0.0
    capital_required_usd: int = 0
    requires_flash_loan: bool = False
    mev_frontrunnable: bool = False
    protocol_pausable: bool = False
    confidence: float = Field(0.0, ge=0.0, le=1.0)

    # Display extras
    contrarian_objections: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Report sections + root document
# ---------------------------------------------------------------------------


class ExecutiveSummary(BaseModel):
    """Top-of-report stats."""

    model_config = ConfigDict(populate_by_name=True)

    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    protocols_analyzed: list[str] = Field(default_factory=list)
    phases_completed: list[int] = Field(default_factory=list)
    total_profit_at_risk_usd: float = 0.0
    earliest_finding_date: Optional[str] = None
    latest_finding_date: Optional[str] = None
    accuracy_summary: dict[str, Any] = Field(default_factory=dict)


class ReportAppendix(BaseModel):
    """Spec: 'Protocol Graph Summary / Invariants Checked / Simulation Results'."""

    model_config = ConfigDict(populate_by_name=True)

    protocol_graph_summary: dict[str, Any] = Field(default_factory=dict)
    invariants_checked: list[dict[str, Any]] = Field(default_factory=list)
    simulation_results: list[dict[str, Any]] = Field(default_factory=list)
    swarm_agent_breakdown: dict[str, Any] = Field(default_factory=dict)


class AuditReport(BaseModel):
    """Root document — round-trips to/from JSON for archival."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str = "ZeroPath Audit Report"
    generated_at: str = Field(default_factory=_utc_now)
    generator_version: str = "0.9.0"

    summary: ExecutiveSummary = Field(default_factory=ExecutiveSummary)
    findings: list[Finding] = Field(default_factory=list)
    appendix: ReportAppendix = Field(default_factory=ReportAppendix)

    analysis_metadata: dict[str, Any] = Field(default_factory=dict)

    # ------------------------------------------------------------------

    @property
    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == SeverityTier.CRITICAL]

    @property
    def has_blocking_findings(self) -> bool:
        return any(f.severity in (SeverityTier.CRITICAL, SeverityTier.HIGH) for f in self.findings)
