"""
Data models for Phase 6: Exploit Validation Engine.

A :class:`ValidationResult` is the verdict on one (hypothesis, simulation)
pair: does the exploit actually work in practice, how bad is it, and is it
already known? This is consumed by:

  Phase 7 — Swarm RL              (learning signal: was the predicted profit real?)
  Phase 8 — Knowledge Graph       (validated exploits become first-class nodes)
  Phase 9 — Audit Report          (severity drives the report tier)

Spec output shape (phases.md, PHASE 6)::

    {
      "valid": true,
      "reason": "...",
      "confidence": 0-1,
      "severity": {
        "profit_tier": "low|medium|high|critical",
        "capital_required_usd": 0,
        "requires_flash_loan": true,
        "time_sensitive": false,
        "mev_frontrunnable": false,
        "protocol_pausable": false
      },
      "duplicate_of": null,
      "contrarian_objections": [],
      "recommended_action": "report|simulate_further|discard"
    }
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ProfitTier(str, Enum):
    """Coarse magnitude bucket used in audit reports."""

    NONE = "none"           # profit <= 0 — should have been rejected
    LOW = "low"             # < $1k
    MEDIUM = "medium"       # $1k – $100k
    HIGH = "high"           # $100k – $1M
    CRITICAL = "critical"   # > $1M


class RecommendedAction(str, Enum):
    """Disposition the validator suggests for the downstream pipeline."""

    REPORT = "report"
    """High-confidence valid exploit — surface in Phase 9 audit report."""

    SIMULATE_FURTHER = "simulate_further"
    """Borderline — re-simulate with mutations or human review."""

    DISCARD = "discard"
    """Invalid, duplicate, or below the minimum severity threshold."""


class RejectionReason(str, Enum):
    """Why the validator rejected an exploit. Used in ValidationResult.reason."""

    PROFIT_NOT_POSITIVE = "profit_not_positive"
    PRIVILEGED_ROLE_REQUIRED = "privileged_role_required"
    UNREALISTIC_LIQUIDITY = "unrealistic_liquidity"
    UNREALISTIC_GAS = "unrealistic_gas"
    SIMULATION_REVERTED = "simulation_reverted"
    SIMULATION_NOT_EXECUTED = "simulation_not_executed"
    SIMULATION_ERROR = "simulation_error"
    DUPLICATE = "duplicate"
    CONTRARIAN_INVALIDATED = "contrarian_invalidated"
    BELOW_SEVERITY_THRESHOLD = "below_severity_threshold"


class ObjectionCategory(str, Enum):
    """High-level class of contrarian objection."""

    MEV_COMPETITION = "mev_competition"
    GAS_LIMIT = "gas_limit"
    LIQUIDITY_DEPTH = "liquidity_depth"
    ADMIN_MITIGATION = "admin_mitigation"
    SANDWICH_RISK = "sandwich_risk"
    BLOCK_REORG = "block_reorg"
    SLIPPAGE = "slippage"
    OTHER = "other"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class SeverityScore(BaseModel):
    """
    CVSS-style multi-dimensional severity. Mirrors the spec's
    ``severity`` sub-object exactly so consumers can serialise directly.
    """

    model_config = ConfigDict(populate_by_name=True)

    profit_tier: ProfitTier = ProfitTier.NONE
    capital_required_usd: int = Field(
        0, ge=0,
        description="Upfront capital the attacker needs in USD. Zero for flash-loan attacks.",
    )
    requires_flash_loan: bool = False
    time_sensitive: bool = Field(
        False,
        description="Exploit only works under specific conditions (stale oracle, governance window).",
    )
    mev_frontrunnable: bool = Field(
        False,
        description="A searcher watching the mempool can extract this attack first.",
    )
    protocol_pausable: bool = Field(
        False,
        description="Protocol admin can pause / freeze, blocking the exploit.",
    )

    # Bonus: composite numeric severity in [0,1] for ranking.
    composite_score: float = Field(0.0, ge=0.0, le=1.0)


class ContrarianObjection(BaseModel):
    """One reason a contrarian agent thinks the exploit will fail in practice."""

    model_config = ConfigDict(populate_by_name=True)

    category: ObjectionCategory = ObjectionCategory.OTHER
    severity: float = Field(
        0.5, ge=0.0, le=1.0,
        description="How damaging this objection is to exploit viability.",
    )
    explanation: str = ""
    evidence: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Core result
# ---------------------------------------------------------------------------


class ValidationResult(BaseModel):
    """
    Verdict on one (hypothesis, simulation) pair.

    The first four fields (``valid``, ``reason``, ``confidence``, ``severity``)
    + ``duplicate_of``, ``contrarian_objections``, ``recommended_action``
    match the Phase 6 spec output shape verbatim. The remaining fields are
    structured extensions for Phase 7 / Phase 8 / Phase 9 consumption.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))

    # ----- Spec output keys -----
    valid: bool = False
    reason: str = ""
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    severity: SeverityScore = Field(default_factory=SeverityScore)
    duplicate_of: Optional[str] = Field(
        None,
        description=(
            "ID of an earlier exploit (Phase 8 KG node) with the same root "
            "cause. None = first time we've seen this."
        ),
    )
    contrarian_objections: list[ContrarianObjection] = Field(default_factory=list)
    recommended_action: RecommendedAction = RecommendedAction.DISCARD

    # ----- Rich extensions -----
    hypothesis_id: str = ""
    sequence_id: str = ""
    simulation_id: str = ""
    protocol_name: str = "unknown"

    rejection_reasons: list[RejectionReason] = Field(default_factory=list)
    fingerprint: str = Field(
        "",
        description="Stable hash over (attack_class, contracts, functions, state vars). "
                    "Used by the Phase 8 KG for deduplication.",
    )
    profit_wei: int = 0
    profit_usd: float = 0.0
    capital_required_usd: int = 0

    analysis_metadata: dict[str, Any] = Field(default_factory=dict)

    # Convenience predicates -------------------------------------------

    @property
    def is_actionable(self) -> bool:
        return self.valid and self.recommended_action == RecommendedAction.REPORT


# ---------------------------------------------------------------------------
# Batch report
# ---------------------------------------------------------------------------


class ValidationReport(BaseModel):
    """
    Aggregate of validation results across a SimulationReport.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    protocol_name: str = "unknown"
    simulation_report_id: str = ""

    results: list[ValidationResult] = Field(default_factory=list)

    # Aggregate stats
    total_validated: int = 0
    valid_count: int = 0
    rejected_count: int = 0
    duplicate_count: int = 0
    report_count: int = 0
    simulate_further_count: int = 0
    discard_count: int = 0

    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    analysis_metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def actionable_results(self) -> list[ValidationResult]:
        return [r for r in self.results if r.is_actionable]

    @property
    def critical_findings(self) -> list[ValidationResult]:
        return [
            r for r in self.results
            if r.severity.profit_tier == ProfitTier.CRITICAL and r.valid
        ]
