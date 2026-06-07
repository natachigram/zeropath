"""Pydantic schemas for the evidence-first ZeroPath engine."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from zeropath.core.utils import utc_now


class CoreModel(BaseModel):
    """Base model with stable JSON behavior."""

    model_config = ConfigDict(populate_by_name=True)


class Asset(CoreModel):
    symbol: str | None = None
    address: str | None = None
    asset_type: str
    chain_id: int | None = None
    decimals: int | None = None
    source: str | None = None


class Role(CoreModel):
    name: str
    address: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    trust_level: str = "unknown"
    source: str | None = None


class TrustBoundary(CoreModel):
    name: str
    boundary_type: str
    description: str
    risk: str
    source: str | None = None


class ExternalDependency(CoreModel):
    name: str
    dependency_type: str
    description: str
    trust_assumption: str
    source: str | None = None


class Invariant(CoreModel):
    id: str
    title: str
    description: str
    invariant_type: str
    protocol_type: str | None = None
    affected_assets: list[str] = Field(default_factory=list)
    affected_contracts: list[str] = Field(default_factory=list)
    severity_if_broken: str = "unknown"
    source: str | None = None
    evidence_level: str = "inferred"


class DeveloperClaim(CoreModel):
    claim: str
    source: str
    mapped_contracts: list[str] = Field(default_factory=list)
    mapped_functions: list[str] = Field(default_factory=list)
    testable_property: str | None = None
    risk_if_false: str | None = None


class ProjectConfig(CoreModel):
    project_id: str
    root_path: str
    adapter: str
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    repo_commit: str | None = None
    scope_files: list[str] = Field(default_factory=list)
    docs_paths: list[str] = Field(default_factory=list)
    source_paths: list[str] = Field(default_factory=list)
    build_system: str | None = None
    chain_context: dict[str, Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProtocolIntent(CoreModel):
    project_id: str
    protocol_name: str | None = None
    protocol_type: str | None = None
    summary: str = ""
    core_assets: list[Asset] = Field(default_factory=list)
    roles: list[Role] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    external_dependencies: list[ExternalDependency] = Field(default_factory=list)
    critical_invariants: list[Invariant] = Field(default_factory=list)
    developer_claims: list[DeveloperClaim] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    confidence: str = "inferred"


class SourceLocation(CoreModel):
    file: str
    contract: str | None = None
    function: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    description: str | None = None


class Impact(CoreModel):
    impact_type: str = "unknown"
    funds_at_risk: bool = False
    measured: bool = False
    amount: str | None = None
    victim: str | None = None
    explanation: str = ""


class EvidenceBundle(CoreModel):
    root_cause_lines_present: bool = False
    attacker_path_present: bool = False
    state_preconditions_present: bool = False
    poc_path: str | None = None
    trace_path: str | None = None
    forge_result: str | None = None
    invariant_test_result: str | None = None
    fork_block: int | None = None
    chain_id: int | None = None
    profit_measured: bool = False
    notes: list[str] = Field(default_factory=list)


class RejectionCheck(CoreModel):
    check_name: str
    passed: bool
    reason: str
    evidence: str | None = None


class CandidateFinding(CoreModel):
    id: str
    project_id: str
    title: str
    status: str = "hypothesis"
    severity_guess: str | None = None
    protocol_type: str | None = None
    bug_class: str | None = None
    affected_invariant: str | None = None
    attacker_model: str | None = None
    entrypoints: list[str] = Field(default_factory=list)
    affected_contracts: list[str] = Field(default_factory=list)
    root_cause_locations: list[SourceLocation] = Field(default_factory=list)
    required_state: list[str] = Field(default_factory=list)
    transaction_sequence: list[str] = Field(default_factory=list)
    impact: Impact = Field(default_factory=Impact)
    evidence: EvidenceBundle = Field(default_factory=EvidenceBundle)
    rejection_checks: list[RejectionCheck] = Field(default_factory=list)
    duplicate_risk: str | None = None
    known_issue_risk: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    tags: list[str] = Field(default_factory=list)
    notes: str = ""


class JudgeResult(CoreModel):
    candidate_id: str
    funds_at_risk: bool
    attacker_realistic: bool
    state_reachable: bool
    live_config_reachable: bool
    known_issue: bool
    duplicate_risk: str
    severity: str
    report_ready: bool
    blocking_objections: list[str] = Field(default_factory=list)
    required_next_steps: list[str] = Field(default_factory=list)
    explanation: str = ""


class MemoryItem(CoreModel):
    id: str
    memory_type: str
    scope: str
    project_id: str | None = None
    content: str
    structured_data: dict[str, Any] = Field(default_factory=dict)
    confidence: str = "inferred"
    source: str
    evidence_refs: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    repo_commit: str | None = None
    file_hashes: dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    last_used_at: datetime | None = None
    times_used: int = 0
    times_confirmed: int = 0
    times_rejected: int = 0
    stale: bool = False
    expires_at: datetime | None = None


class MemoryDecision(CoreModel):
    save: bool
    memory_type: str | None = None
    scope: str | None = None
    confidence: str | None = None
    reason: str
    tags: list[str] = Field(default_factory=list)


class ExploitPattern(CoreModel):
    id: str
    name: str
    protocol_types: list[str] = Field(default_factory=list)
    ecosystems: list[str] = Field(default_factory=list)
    violated_invariant: str
    required_conditions: list[str] = Field(default_factory=list)
    anti_conditions: list[str] = Field(default_factory=list)
    proof_shape: list[str] = Field(default_factory=list)
    common_false_positives: list[str] = Field(default_factory=list)
    impact_types: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class AdapterDetection(CoreModel):
    adapter: str
    confidence: str
    reasons: list[str] = Field(default_factory=list)
    build_system: str | None = None
    files_detected: list[str] = Field(default_factory=list)
