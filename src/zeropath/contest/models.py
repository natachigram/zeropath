"""
Data models for the Contest module.

Every contest run produces a :class:`ContestReport` that bundles:

  * The :class:`ContestConfig` (platform, scope, deadline, budget)
  * All :class:`Submission` rows ready to send to the platform
  * Cost ledger + telemetry

The :class:`Submission` model is platform-agnostic; platform-specific
formatters in :mod:`contest.platforms` render each submission into the
exact JSON/Markdown the platform expects.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ContestPlatform(str, Enum):
    CANTINA = "cantina"
    CODE4RENA = "code4rena"
    SHERLOCK = "sherlock"
    IMMUNEFI = "immunefi"
    GENERIC = "generic"


class SubmissionDisposition(str, Enum):
    """What the strategy module decides to do with each finding."""

    SUBMIT_NOW = "submit_now"           # high-conviction + low-dup → send first
    SUBMIT_LATER = "submit_later"       # lower priority, may be duplicate
    HOLD = "hold"                       # below confidence gate
    DISCARD = "discard"                 # contrarian invalidated


# ---------------------------------------------------------------------------
# Config + scope
# ---------------------------------------------------------------------------


class ContestConfig(BaseModel):
    """All knobs that drive a contest run."""

    model_config = ConfigDict(populate_by_name=True)

    platform: ContestPlatform = ContestPlatform.GENERIC
    contest_name: str = ""
    repo_path: str = "./contracts"
    scope_files: list[str] = Field(
        default_factory=list,
        description="In-scope files (relative paths). Empty = all .sol under repo_path.",
    )
    out_of_scope_files: list[str] = Field(default_factory=list)
    deadline_utc: Optional[str] = None

    # Budgets
    llm_budget_usd: Optional[float] = Field(
        200.0,
        description="Hard cap on LLM spend. None = unlimited.",
    )
    max_seconds: Optional[int] = Field(
        None, description="Wall-clock cap. None = until done.",
    )

    # Quality gates
    submit_confidence_threshold: float = Field(0.70, ge=0.0, le=1.0)
    submit_severity_floor: str = Field("medium")    # "low" allows everything
    max_findings_per_file: int = 10

    # Pipeline toggles
    use_llm: bool = True
    use_spec_miner: bool = True
    use_foundry_verifier: bool = True
    use_contrarian: bool = True

    # Concurrency
    parallel_workers: int = 4

    # Provenance
    started_at: str = Field(default_factory=_utc_now)


# ---------------------------------------------------------------------------
# Submission
# ---------------------------------------------------------------------------


class SubmissionFinding(BaseModel):
    """Platform-agnostic finding payload."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    severity: str = "medium"                # critical / high / medium / low / info
    attack_class: str = "other"

    contracts_involved: list[str] = Field(default_factory=list)
    functions_involved: list[str] = Field(default_factory=list)
    lines_of_code: list[str] = Field(
        default_factory=list,
        description="Permalink-style refs: 'github.com/owner/repo/blob/SHA/path#L1-L20'",
    )

    description: str = ""
    impact: str = ""
    attack_path: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    proof_of_concept_code: str = ""
    proof_of_concept_run_log: str = ""
    recommendation: str = ""

    confidence: float = Field(0.5, ge=0.0, le=1.0)
    duplicate_likelihood: float = Field(
        0.5, ge=0.0, le=1.0,
        description="0 = unique; 1 = guaranteed duplicate among competitors.",
    )

    # Provenance back through ZeroPath
    hypothesis_id: str = ""
    validation_result_id: str = ""
    spec_claim_source: Optional[str] = None
    novelty_assessment: str = ""

    historical_precedents: list[dict[str, Any]] = Field(default_factory=list)
    contrarian_objections: list[str] = Field(default_factory=list)


class Submission(BaseModel):
    """A single finding queued for submission, with disposition metadata."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    finding: SubmissionFinding
    disposition: SubmissionDisposition = SubmissionDisposition.HOLD
    rank: int = 0
    rendered_payload: Optional[dict[str, Any]] = Field(
        None,
        description="Platform-rendered payload ready to POST/submit.",
    )
    submitted_at: Optional[str] = None
    platform: ContestPlatform = ContestPlatform.GENERIC

    @property
    def is_actionable(self) -> bool:
        return self.disposition in (
            SubmissionDisposition.SUBMIT_NOW,
            SubmissionDisposition.SUBMIT_LATER,
        )


# ---------------------------------------------------------------------------
# Contest report
# ---------------------------------------------------------------------------


class ContestReport(BaseModel):
    """Root output of one contest run."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    config: ContestConfig

    submissions: list[Submission] = Field(default_factory=list)

    # Aggregate stats
    files_scanned: int = 0
    raw_findings_count: int = 0
    valid_findings_count: int = 0
    submitted_count: int = 0
    discarded_count: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)

    # Cost / telemetry
    llm_spent_usd: float = 0.0
    llm_calls: int = 0
    elapsed_seconds: float = 0.0
    started_at: str = Field(default_factory=_utc_now)
    ended_at: Optional[str] = None

    analysis_metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def ready_to_submit(self) -> list[Submission]:
        return sorted(
            (s for s in self.submissions if s.is_actionable),
            key=lambda s: s.rank,
        )

    @property
    def critical_count(self) -> int:
        return sum(1 for s in self.submissions if s.finding.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for s in self.submissions if s.finding.severity == "high")
