"""
Data models for Phase 5: EVM Simulation Engine.

A :class:`SimulationResult` is the canonical record of one
``TransactionSequence`` executed against an Anvil fork. It is consumed by:

  Phase 6 — Exploit Validation Engine (profit / realism check)
  Phase 7 — Swarm RL  (shaped-reward learning signal)
  Phase 8 — Knowledge Graph (deduplication, post-mortem indexing)
  Phase 4 — sequence generator (revert info → mutation guidance)

Spec output shape (phases.md, PHASE 5)::

    {
      "success": true,
      "profit_wei": 0,
      "profit_usd": 0,
      "state_diff": {},
      "events_emitted": [],
      "gas_used": 0,
      "revert_reason": null,
      "revert_call_stack": [],
      "fuzzer_violations": [],
      "halmos_result": "proved|falsified|unknown",
      "block_number": 0,
      "fork_url": ""
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


class HalmosResult(str, Enum):
    """Outcome of a Halmos symbolic-execution run against an invariant."""

    PROVED = "proved"
    """No input violates the invariant within Halmos' bounded model."""

    FALSIFIED = "falsified"
    """Halmos found a concrete counter-example."""

    UNKNOWN = "unknown"
    """Out of memory, timeout, or invariant outside Halmos' supported subset."""

    SKIPPED = "skipped"
    """Halmos was not installed or no formal_spec was attached."""


class FuzzerKind(str, Enum):
    ECHIDNA = "echidna"
    MEDUSA = "medusa"
    NONE = "none"


class SimulationOutcome(str, Enum):
    """High-level outcome flag used by orchestrators when filtering."""

    PROFITABLE = "profitable"
    """The sequence executed and the attacker ended ETH-positive."""

    EXECUTED_NO_PROFIT = "executed_no_profit"
    """Ran to completion but extracted no measurable value."""

    REVERTED = "reverted"
    """One of the steps reverted; downstream phases should look at revert_info."""

    SIMULATION_ERROR = "simulation_error"
    """Anvil/RPC error — distinct from an in-EVM revert."""

    NOT_EXECUTED = "not_executed"
    """Skipped because the sequence was incomplete or empty."""


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class StepResult(BaseModel):
    """Per-call execution telemetry."""

    model_config = ConfigDict(populate_by_name=True)

    step: int
    tx_hash: Optional[str] = None
    status: str = Field("pending", description="success | reverted | rpc_error")
    gas_used: int = 0
    revert_reason: Optional[str] = None
    return_data_hex: Optional[str] = None
    logs: list[dict[str, Any]] = Field(default_factory=list)
    block_number: Optional[int] = None


class BalanceDiff(BaseModel):
    """Pre/post balance delta for one (account, asset) pair."""

    model_config = ConfigDict(populate_by_name=True)

    account: str
    asset: str = Field("ETH", description="'ETH' or 0x-prefixed token address")
    before: int = 0
    after: int = 0

    @property
    def delta(self) -> int:
        return self.after - self.before


class StorageDiff(BaseModel):
    """Pre/post raw storage delta for a (contract, slot) pair."""

    model_config = ConfigDict(populate_by_name=True)

    contract: str
    slot: str
    before: str
    after: str


class RevertInfo(BaseModel):
    """
    Structured revert telemetry — fed back to Phase 4 as mutation guidance.

    Spec (phases.md, PHASE 5, "Revert analysis"):
        "When a sequence fails (reverts), capture the full revert reason,
         the call stack at revert, and the state delta up to the revert
         point. Feed this back to Phase 4 as mutation guidance."
    """

    model_config = ConfigDict(populate_by_name=True)

    step: int = Field(description="Step number that reverted")
    reason: str = Field(description="Decoded revert string or 4-byte selector")
    call_stack: list[str] = Field(
        default_factory=list,
        description="Call stack at the revert frame (innermost first).",
    )
    raw_return_data: Optional[str] = None
    suggested_mutation: Optional[str] = Field(
        None,
        description=(
            "Plain-English suggestion for Phase 4 mutation engine "
            "(e.g. 'approve() before transferFrom()')."
        ),
    )


class FuzzerViolation(BaseModel):
    """One property failure surfaced by Echidna / Medusa."""

    model_config = ConfigDict(populate_by_name=True)

    fuzzer: FuzzerKind
    property_name: str
    invariant_id: Optional[str] = Field(
        None,
        description="Phase 2 Invariant.id this property maps to, when known.",
    )
    counter_example_calls: list[str] = Field(
        default_factory=list,
        description="Sequence of calls that violated the property.",
    )
    shrunk: bool = False
    runs: int = 0
    raw_report: str = ""


class HalmosCheck(BaseModel):
    """Result of running Halmos against one Phase 2 formal_spec."""

    model_config = ConfigDict(populate_by_name=True)

    invariant_id: str
    formal_spec: str
    result: HalmosResult
    counter_example: Optional[str] = None
    elapsed_seconds: float = 0.0
    notes: str = ""


# ---------------------------------------------------------------------------
# Core simulation result
# ---------------------------------------------------------------------------


class SimulationResult(BaseModel):
    """
    Complete record of one ``TransactionSequence`` executed on an Anvil fork.

    Mirrors the spec's required JSON shape but adds structured sub-models so
    Phase 6 / Phase 7 / Phase 8 can consume rich telemetry without re-parsing.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    sequence_id: str
    hypothesis_id: str = ""
    protocol_name: str = "unknown"

    # ----- Spec output keys -----
    success: bool = False
    profit_wei: int = 0
    profit_usd: float = 0.0
    state_diff: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form structured state delta — see balance_diffs / storage_diffs for typed forms.",
    )
    events_emitted: list[dict[str, Any]] = Field(default_factory=list)
    gas_used: int = 0
    revert_reason: Optional[str] = None
    revert_call_stack: list[str] = Field(default_factory=list)
    fuzzer_violations: list[FuzzerViolation] = Field(default_factory=list)
    halmos_result: HalmosResult = HalmosResult.SKIPPED
    block_number: int = 0
    fork_url: str = ""

    # ----- Rich telemetry (extensions over the spec) -----
    outcome: SimulationOutcome = SimulationOutcome.NOT_EXECUTED
    step_results: list[StepResult] = Field(default_factory=list)
    balance_diffs: list[BalanceDiff] = Field(default_factory=list)
    storage_diffs: list[StorageDiff] = Field(default_factory=list)
    revert_info: Optional[RevertInfo] = None
    halmos_checks: list[HalmosCheck] = Field(default_factory=list)

    # Reproducibility metadata
    chain_id: int = 1
    fork_url_scrubbed: str = ""
    anvil_version: str = ""
    elapsed_seconds: float = 0.0
    deterministic: bool = True

    # Convenience predicates ---------------------------------------------

    @property
    def is_profitable(self) -> bool:
        return self.success and self.profit_wei > 0

    @property
    def reverted(self) -> bool:
        return self.outcome == SimulationOutcome.REVERTED

    @property
    def has_fuzzer_violations(self) -> bool:
        return bool(self.fuzzer_violations)

    @property
    def halmos_falsified(self) -> bool:
        return self.halmos_result == HalmosResult.FALSIFIED


# ---------------------------------------------------------------------------
# Batch report
# ---------------------------------------------------------------------------


class SimulationReport(BaseModel):
    """
    Aggregate result of running an entire Phase 4 SequenceReport through
    the simulator.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    protocol_name: str = "unknown"
    sequence_report_id: str = ""

    results: list[SimulationResult] = Field(default_factory=list)

    # Aggregate stats
    sequences_executed: int = 0
    sequences_profitable: int = 0
    sequences_reverted: int = 0
    sequences_skipped: int = 0
    total_profit_wei: int = 0
    total_gas_used: int = 0

    analysis_metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def profitable_results(self) -> list[SimulationResult]:
        return [r for r in self.results if r.is_profitable]

    @property
    def reverted_results(self) -> list[SimulationResult]:
        return [r for r in self.results if r.reverted]
