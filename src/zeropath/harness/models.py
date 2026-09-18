"""Durable models for the evidence-first ZeroPath harness.

The harness deliberately keeps campaign control-plane state separate from the
candidate database.  CandidateFinding remains the domain object for a possible
finding; these models describe how a bounded, replayable campaign got there.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from zeropath.core.utils import utc_now


class HarnessModel(BaseModel):
    """Base model with stable JSON serialization for on-disk artifacts."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")


HarnessPhase = Literal["frame", "hunt", "bank", "verify", "defend", "paused", "complete"]
HarnessStatus = Literal["active", "paused", "blocked", "complete"]
CheckpointStatus = Literal[
    "not_started",
    "advanced",
    "falsified",
    "operational-failure",
    "denied",
    "paused",
    "complete",
]
Outcome = Literal["not_tested", "tested", "blocked", "excluded", "not_applicable", "retest"]
BackendStatus = Literal[
    "passed",
    "failed",
    "no_tests",
    "unavailable",
    "timeout",
    "blocked",
    "skipped",
    "unknown",
]


class HarnessCheckpoint(HarnessModel):
    """The exact durable handoff for one material action."""

    status: CheckpointStatus = "not_started"
    last_completed: str = ""
    last_command: str = ""
    last_observation: str = ""
    result_class: str = ""
    files_written: list[str] = Field(default_factory=list)
    next_action: str = ""


class HarnessActor(HarnessModel):
    """An abstract role used by local fixtures, never a real identity."""

    id: str
    trust: str
    source: str
    capabilities: list[str] = Field(default_factory=list)


class HarnessOperation(HarnessModel):
    """One entry point in the selected flow's coverage ledger."""

    id: str
    area: str
    entry_point: str
    caller_class: str
    state_touched: list[str] = Field(default_factory=list)
    invariants: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    outcome: Outcome = "not_tested"
    evidence: list[str] = Field(default_factory=list)
    observed_result: str = ""
    next_action: str = ""


class HarnessCoverage(HarnessModel):
    """Operation-level accounting; tested never means safe."""

    schema_version: int = 1
    source_digest: str = ""
    reference_lock_digest: str = ""
    last_updated: datetime = Field(default_factory=utc_now)
    operations: list[HarnessOperation] = Field(default_factory=list)


class HarnessQueueItem(HarnessModel):
    """A candidate routed through Hunt-style admission and verification."""

    id: str
    area: str
    priority: int = 0
    impact_classes: list[str] = Field(default_factory=list)
    target_invariant: str = ""
    entry_points: list[str] = Field(default_factory=list)
    attacker_model: str = ""
    preconditions: list[str] = Field(default_factory=list)
    hypothesis: str = ""
    discovery_stream: str = "source-native"
    mechanism_tags: list[str] = Field(default_factory=list)
    precision_bucket: Literal["A", "B", "C", ""] = ""
    precision_gate: dict[str, str] = Field(default_factory=dict)
    transaction_sequence: list[str] = Field(default_factory=list)
    reality_anchor: str = ""
    status: Literal[
        "not_started",
        "mapping",
        "active",
        "blocked",
        "disproven",
        "candidate",
        "proven",
        "duplicate",
        "known_issue",
        "out_of_scope",
    ] = "not_started"
    evidence: list[str] = Field(default_factory=list)
    reopen_condition: str = ""
    notes: str = ""


class HarnessQueue(HarnessModel):
    """Persisted attack-surface queue with provenance-preserving cards."""

    schema_version: int = 1
    audited_commit: str | None = None
    reference_lock_digest: str = ""
    workers: dict[str, Any] = Field(default_factory=dict)
    items: list[HarnessQueueItem] = Field(default_factory=list)


class BackendRun(HarnessModel):
    """A bounded local backend invocation and its primary observation."""

    run_id: str
    campaign_id: str
    backend: str
    status: BackendStatus
    command: list[str] = Field(default_factory=list)
    cwd: str = ""
    target_path: str | None = None
    seed: int | None = None
    verbosity: int = 0
    timeout_seconds: int = 0
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    source_digest_before: str = ""
    source_digest_after: str = ""
    evidence_path: str | None = None
    replay_of: str | None = None
    error: str | None = None


class CorpusAction(HarnessModel):
    """A replayable abstract operation used by stateful harness adapters."""

    operation_id: str
    name: str
    arguments: list[Any] = Field(default_factory=list)
    caller: str = "attacker"


class CorpusCase(HarnessModel):
    """A minimized or discovered stateful sequence."""

    case_id: str
    seed: int
    depth: int
    actions: list[CorpusAction] = Field(default_factory=list)
    status: Literal["generated", "replayed", "failed", "shrunk", "passed"] = "generated"
    invariant_id: str | None = None
    failure_fingerprint: str | None = None
    backend_run_id: str | None = None
    notes: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class HarnessManifest(HarnessModel):
    """Run manifest and recovery state for one isolated campaign."""

    schema_version: int = 1
    campaign_id: str
    project_id: str
    target_root: str
    task: Literal["new-hunt", "continue"] = "new-hunt"
    engagement_mode: Literal["quick", "contest", "bounty"] = "quick"
    budget: Literal["small", "standard", "extended"] = "standard"
    access_mode: Literal["local-only", "public-read", "simulation-write"] = "local-only"
    status: HarnessStatus = "active"
    phase: HarnessPhase = "frame"
    audited_ref_type: Literal["git_commit", "source_tree"] = "git_commit"
    audited_commit: str | None = None
    source_paths: list[str] = Field(default_factory=list)
    source_digest: str = ""
    scope_digest: str = ""
    reference_lock_digest: str = ""
    backends: list[str] = Field(default_factory=lambda: ["foundry"])
    seed: int = 1
    started_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    active_candidate_id: str | None = None
    active_hypothesis: str | None = None
    limits: dict[str, Any] = Field(default_factory=dict)
    actors: list[HarnessActor] = Field(default_factory=list)
    toolchain: dict[str, Any] = Field(default_factory=dict)
    checkpoint: HarnessCheckpoint = Field(default_factory=HarnessCheckpoint)


class HarnessMetrics(HarnessModel):
    """Paired workflow metrics; none are safety claims."""

    schema_version: int = 1
    last_updated: datetime = Field(default_factory=utc_now)
    counters: dict[str, int] = Field(default_factory=dict)
    precision: dict[str, int] = Field(default_factory=dict)
    quality: dict[str, int] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


class HarnessEvent(HarnessModel):
    """Append-only event used to rebuild or audit materialized campaign state."""

    sequence: int
    event_id: str
    campaign_id: str
    event_type: str
    phase: HarnessPhase
    timestamp: datetime = Field(default_factory=utc_now)
    payload: dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "BackendRun",
    "BackendStatus",
    "CorpusAction",
    "CorpusCase",
    "HarnessActor",
    "HarnessCheckpoint",
    "HarnessCoverage",
    "HarnessEvent",
    "HarnessManifest",
    "HarnessMetrics",
    "HarnessOperation",
    "HarnessPhase",
    "HarnessQueue",
    "HarnessQueueItem",
    "HarnessStatus",
    "Outcome",
]
