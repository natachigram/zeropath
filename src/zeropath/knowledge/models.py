"""
Pydantic models for Phase 8: Knowledge Graph + Memory System.

These records are the persisted form of every fact the system has learned —
exploits we validated, external incidents we ingested, predictions we made,
and the accuracy outcome of each.

All models are JSON-serialisable so the in-memory and Neo4j stores share an
identical wire format.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from zeropath.knowledge.schema import NodeLabel, RelationshipType


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class IntelSource(str, Enum):
    """Provenance of external threat-intel records."""

    DEFIHACKLABS = "defihacklabs"
    REKT = "rekt"
    IMMUNEFI = "immunefi"
    CHAINALYSIS = "chainalysis"
    MANUAL = "manual"
    OTHER = "other"


class InferenceKind(str, Enum):
    """Which earlier phase produced an :class:`InferenceRecord`."""

    INVARIANT = "invariant"               # Phase 2
    ATTACK_HYPOTHESIS = "attack_hypothesis"   # Phase 3
    RL_DISCOVERED = "rl_discovered"       # Phase 7


class ValidationOutcome(str, Enum):
    """How an :class:`InferenceRecord` was eventually resolved."""

    VALIDATED = "validated"
    INVALIDATED = "invalidated"
    PENDING = "pending"
    DUPLICATE = "duplicate"


# ---------------------------------------------------------------------------
# Graph primitives — used by InMemoryKGStore and dumped by Neo4jKGStore
# ---------------------------------------------------------------------------


class KGNode(BaseModel):
    """Generic in-memory representation of a graph node."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    label: NodeLabel
    properties: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=_utc_now)
    updated_at: str = Field(default_factory=_utc_now)


class KGEdge(BaseModel):
    """Generic in-memory representation of a graph edge."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    from_id: str
    to_id: str
    type: RelationshipType
    properties: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=_utc_now)


# ---------------------------------------------------------------------------
# Core domain records
# ---------------------------------------------------------------------------


class ExternalIncidentRecord(BaseModel):
    """
    Normalised external threat-intel entry (one rekt incident, one Immunefi
    post-mortem, etc.).

    Spec (phases.md, PHASE 8, "External threat intelligence"):
        "Ingest and normalize data from DeFiHackLabs, Rekt.news, Immunefi
         post-mortems, Chainalysis. Store as first-class graph nodes."
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    source: IntelSource = IntelSource.OTHER
    protocol: str = Field(description="Protocol/contract that was exploited")
    chain: str = "ethereum"
    incident_date: Optional[str] = Field(
        None, description="ISO-8601 date of the public incident"
    )
    attack_class: str = Field("unknown", description="Phase 3 AttackClass.value")
    loss_usd: int = Field(0, ge=0)
    root_cause: str = ""
    affected_functions: list[str] = Field(default_factory=list)
    affected_addresses: list[str] = Field(default_factory=list)
    source_url: str = ""
    tags: list[str] = Field(default_factory=list)
    raw_payload: Optional[dict[str, Any]] = Field(
        None,
        description=(
            "Original record from the upstream feed. Kept for traceability."
        ),
    )


class ExploitRecord(BaseModel):
    """
    A Phase 6 validated exploit promoted into the knowledge graph.

    Carries the link back to every artefact that produced it so Phase 9
    audit-report generation can render the full provenance chain.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    protocol_name: str
    attack_class: str
    fingerprint: str
    severity_tier: str = "low"
    profit_wei: int = 0
    profit_usd: float = 0.0
    capital_required_usd: int = 0
    confidence: float = Field(0.0, ge=0.0, le=1.0)

    # Cross-references
    hypothesis_id: str = ""
    sequence_id: str = ""
    simulation_id: str = ""
    invariant_ids: list[str] = Field(default_factory=list)

    contracts_involved: list[str] = Field(default_factory=list)
    functions_involved: list[str] = Field(default_factory=list)
    state_vars_involved: list[str] = Field(default_factory=list)

    recorded_at: str = Field(default_factory=_utc_now)
    matched_incidents: list[str] = Field(
        default_factory=list,
        description="External incident IDs that share root cause.",
    )


class UpgradeEventRecord(BaseModel):
    """
    A protocol upgrade observed via Phase 1's version-diff mode.

    Spec (phases.md, PHASE 8, "Temporal pattern analysis"):
        "Track when vulnerabilities were introduced relative to protocol
         upgrades. The pattern 'upgrade → new vulnerability within 30 days'
         is a real signal."
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    protocol_name: str
    upgrade_date: str = Field(default_factory=_utc_now)
    added_functions: list[str] = Field(default_factory=list)
    changed_state_variables: list[str] = Field(default_factory=list)
    new_external_dependencies: list[str] = Field(default_factory=list)
    notes: str = ""


class InferenceRecord(BaseModel):
    """
    One prediction the system made, with its eventual validation outcome.

    The :class:`FeedbackLoopTracker` rolls these up into accuracy metrics
    per attack class and per protocol type.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    kind: InferenceKind = InferenceKind.INVARIANT
    protocol_name: str = ""
    attack_class: str = ""
    description: str = ""
    confidence_at_prediction: float = Field(0.0, ge=0.0, le=1.0)
    predicted_at: str = Field(default_factory=_utc_now)

    # Outcome
    outcome: ValidationOutcome = ValidationOutcome.PENDING
    resolved_at: Optional[str] = None
    resolution_exploit_id: Optional[str] = Field(
        None,
        description="ID of the ExploitRecord that validated this inference, if any.",
    )

    # Provenance back to the source artefact
    source_phase: int = 0       # 2 (invariant), 3 (hypothesis), 7 (rl)
    source_id: str = ""


# ---------------------------------------------------------------------------
# Aggregate metric record
# ---------------------------------------------------------------------------


class AccuracyMetric(BaseModel):
    """
    Roll-up accuracy across a slice of :class:`InferenceRecord` rows.

    Spec (phases.md, PHASE 8, "Feedback loop quality measurement"):
        "Track prediction accuracy: log every inference made and whether it
         was validated. Surface accuracy metrics per attack class and per
         protocol type."
    """

    model_config = ConfigDict(populate_by_name=True)

    dimension: str = Field(description="'attack_class' | 'protocol' | 'overall'")
    key: str = Field(description="The specific value sliced on (e.g. 'oracle_manipulation')")
    total: int = 0
    validated: int = 0
    invalidated: int = 0
    pending: int = 0
    duplicate: int = 0

    @property
    def precision(self) -> float:
        decided = self.validated + self.invalidated
        if decided <= 0:
            return 0.0
        return round(self.validated / decided, 4)

    @property
    def recall_proxy(self) -> float:
        """
        How many predictions ended in a validated exploit?
        Proxy for recall — we can't compute true recall without an
        oracle set of all "real" bugs.
        """
        if self.total <= 0:
            return 0.0
        return round(self.validated / self.total, 4)


# ---------------------------------------------------------------------------
# Similarity result
# ---------------------------------------------------------------------------


class SimilarityHit(BaseModel):
    """One similarity-query hit returned by :class:`SimilarityEngine`."""

    model_config = ConfigDict(populate_by_name=True)

    target_id: str
    target_label: NodeLabel
    target_name: str = ""
    score: float = Field(0.0, ge=0.0, le=1.0)
    reason: str = ""

    # Convenience: the dict properties from the matched node.
    properties: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Knowledge-graph report (root output of an orchestrator run)
# ---------------------------------------------------------------------------


class KnowledgeReport(BaseModel):
    """Aggregate output of one KnowledgeGraphOrchestrator pass."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    protocol_name: str = "unknown"

    exploits_ingested: int = 0
    incidents_ingested: int = 0
    inferences_recorded: int = 0
    similarity_hits: list[SimilarityHit] = Field(default_factory=list)
    accuracy_metrics: list[AccuracyMetric] = Field(default_factory=list)

    analysis_metadata: dict[str, Any] = Field(default_factory=dict)
