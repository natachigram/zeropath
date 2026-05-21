"""
KnowledgeGraphOrchestrator — Phase 8 top-level coordinator.

Stitches the Phase 8 sub-components into a single façade. A typical end-to-end
session::

    kg = KnowledgeGraphOrchestrator()
    kg.ingest_invariant_report(inv_report)
    kg.ingest_validation_report(validation_report)
    kg.ingest_threat_intel(IntelSource.DEFIHACKLABS, defihacklabs_entries)
    confidence_boost = kg.lookup_historical_grounding(hypothesis)
    similar = kg.find_similar_exploits(exploit_id)
    accuracy = kg.feedback.accuracy_by_attack_class()

The orchestrator is what Phase 3 swarm agents query before generating
hypotheses (per spec, "Phase 3 agents query this graph before generating
hypotheses. Confidence of hypotheses matching historical patterns is
boosted automatically.") — exposed via :meth:`lookup_historical_grounding`.
"""

from __future__ import annotations

import logging
import time
from typing import Iterable, Optional

from zeropath.adversarial.models import AttackHypothesis, SwarmReport
from zeropath.invariants.models import InvariantReport
from zeropath.knowledge.feedback_loop import FeedbackLoopTracker
from zeropath.knowledge.graphrag import GraphRAGAdapter, GraphSummary
from zeropath.knowledge.ingestion import IngestionEngine
from zeropath.knowledge.models import (
    AccuracyMetric,
    ExploitRecord,
    ExternalIncidentRecord,
    IntelSource,
    InferenceKind,
    KnowledgeReport,
    SimilarityHit,
    UpgradeEventRecord,
    ValidationOutcome,
)
from zeropath.knowledge.schema import NodeLabel
from zeropath.knowledge.similarity import SimilarityEngine
from zeropath.knowledge.store import InMemoryKGStore, KGStore
from zeropath.knowledge.temporal import TemporalAnalyzer, TemporalSummary
from zeropath.knowledge.threat_intel import ThreatIntelIngestor
from zeropath.models import ProtocolGraph
from zeropath.validation.models import ValidationReport, ValidationResult

logger = logging.getLogger(__name__)


# A hypothesis whose attack class is well-attested in the KG gets up to
# this much extra confidence injected by Phase 3 before debate.
_MAX_HISTORICAL_BOOST = 0.15


class KnowledgeGraphOrchestrator:
    """
    Single entry point for Phase 8.

    Parameters
    ----------
    store : KGStore | None
        Backend. Defaults to :class:`InMemoryKGStore`.
    only_actionable : bool
        Forwarded to :class:`IngestionEngine`.
    graphrag : GraphRAGAdapter | None
        Override the default adapter (e.g. inject a configured one).
    """

    def __init__(
        self,
        store: Optional[KGStore] = None,
        *,
        only_actionable: bool = True,
        graphrag: Optional[GraphRAGAdapter] = None,
    ) -> None:
        self.store: KGStore = store or InMemoryKGStore()
        self.ingestor = IngestionEngine(self.store, only_actionable=only_actionable)
        self.intel = ThreatIntelIngestor(self.ingestor)
        self.similarity = SimilarityEngine(self.store)
        self.temporal = TemporalAnalyzer(self.store)
        self.feedback = FeedbackLoopTracker(self.store)
        self.graphrag = graphrag or GraphRAGAdapter(self.store)

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest_protocol_graph(self, graph: ProtocolGraph, protocol_name: str):
        return self.ingestor.ingest_protocol_graph(graph, protocol_name)

    def ingest_invariant_report(self, report: InvariantReport):
        nodes = self.ingestor.ingest_invariant_report(report)
        # Each invariant becomes a Phase-2 inference whose outcome we'll
        # resolve later via reconcile_with_validation.
        for inv in report.invariants:
            self.feedback.record_invariant_inference(
                invariant_id=inv.id,
                protocol_name=report.protocol_name,
                attack_class=str(inv.type.value),
                description=inv.description[:200],
                confidence=inv.confidence,
            )
        return nodes

    def ingest_swarm_report(self, report: SwarmReport):
        """Record each Phase 3 hypothesis as a PENDING inference."""
        for h in report.hypotheses:
            self.feedback.record_hypothesis_inference(
                hypothesis_id=h.id,
                protocol_name=report.protocol_name,
                attack_class=h.attack_class.value,
                description=h.title,
                confidence=h.confidence,
            )

    def ingest_validation_result(
        self,
        result: ValidationResult,
        *,
        protocol_name: Optional[str] = None,
    ) -> Optional[ExploitRecord]:
        record = self.ingestor.ingest_validation_result(
            result, protocol_name=protocol_name,
        )
        # Resolve any matching Phase-3 hypothesis inference.
        if result.hypothesis_id and record is not None:
            self.feedback.reconcile(
                source_id=result.hypothesis_id,
                outcome=ValidationOutcome.VALIDATED,
                exploit_id=record.id,
            )
        elif result.hypothesis_id and not result.valid:
            self.feedback.reconcile(
                source_id=result.hypothesis_id,
                outcome=(
                    ValidationOutcome.DUPLICATE if result.duplicate_of
                    else ValidationOutcome.INVALIDATED
                ),
                exploit_id=result.duplicate_of,
                reason=result.reason,
            )
        return record

    def ingest_validation_report(
        self, report: ValidationReport,
    ) -> list[ExploitRecord]:
        out: list[ExploitRecord] = []
        for r in report.results:
            rec = self.ingest_validation_result(r, protocol_name=report.protocol_name)
            if rec is not None:
                out.append(rec)
        return out

    def ingest_threat_intel(
        self, source: IntelSource, entries: Iterable[dict],
    ) -> list[ExternalIncidentRecord]:
        records, _stats = self.intel.ingest_entries(source, entries)
        return records

    def ingest_upgrade_event(self, record: UpgradeEventRecord):
        return self.ingestor.ingest_upgrade_event(record)

    # ------------------------------------------------------------------
    # Phase 3 grounding query
    # ------------------------------------------------------------------

    def lookup_historical_grounding(
        self,
        hypothesis: AttackHypothesis,
        *,
        max_boost: float = _MAX_HISTORICAL_BOOST,
    ) -> tuple[float, list[ExternalIncidentRecord]]:
        """
        Spec (Phase 8 LLM prompt):
            "Phase 3 agents query this graph before generating hypotheses.
             Confidence of hypotheses matching historical patterns is
             boosted automatically."

        Returns ``(confidence_boost, matched_incidents)`` where
        ``confidence_boost`` ∈ [0, max_boost].
        """
        target_class = hypothesis.attack_class.value
        contracts = {c.lower() for c in hypothesis.contracts_involved or []}
        matches: list[ExternalIncidentRecord] = []
        for node in self.store.find_by_label(NodeLabel.EXTERNAL_INCIDENT):
            if node.properties.get("attack_class") != target_class:
                continue
            incident_protocol = (node.properties.get("protocol") or "").lower()
            shared = contracts and incident_protocol in contracts
            matches.append(ExternalIncidentRecord.model_validate(node.properties))
            if shared:
                # Direct protocol match gets the full boost.
                return min(max_boost, max_boost), matches
        if not matches:
            return 0.0, []
        # Same class but different protocol → smaller boost proportional to
        # how many incidents back it (logistic-ish saturation).
        n = len(matches)
        boost = min(max_boost, max_boost * (n / (n + 3)))
        return round(boost, 4), matches

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def find_similar_protocols(self, protocol_name: str) -> list[SimilarityHit]:
        return self.similarity.find_similar_protocols(protocol_name)

    def find_similar_exploits(self, exploit_id: str) -> list[SimilarityHit]:
        return self.similarity.find_similar_exploits(exploit_id)

    def find_invariants_matching_incident(self, incident_id: str) -> list[SimilarityHit]:
        return self.similarity.find_invariants_matching_incident(incident_id)

    def temporal_summary(self, protocol_name: str) -> TemporalSummary:
        return self.temporal.summarise(protocol_name)

    def global_summaries(self) -> list[GraphSummary]:
        return self.graphrag.global_summaries()

    def local_summaries(self) -> list[GraphSummary]:
        return self.graphrag.local_summaries()

    def motif_summaries(self, *, min_support: int = 2) -> list[GraphSummary]:
        return self.graphrag.motif_summaries(min_support=min_support)

    # ------------------------------------------------------------------
    # Headline rollup — what an audit dashboard would display
    # ------------------------------------------------------------------

    def report(self, *, protocol_name: str = "unknown") -> KnowledgeReport:
        start = time.monotonic()
        exploits = self.store.find_by_label(NodeLabel.VALIDATED_EXPLOIT)
        incidents = self.store.find_by_label(NodeLabel.EXTERNAL_INCIDENT)
        inferences = self.store.find_by_label(NodeLabel.INFERENCE)
        metrics: list[AccuracyMetric] = self.feedback.all_metrics()
        return KnowledgeReport(
            protocol_name=protocol_name,
            exploits_ingested=len(exploits),
            incidents_ingested=len(incidents),
            inferences_recorded=len(inferences),
            accuracy_metrics=metrics,
            analysis_metadata={
                "elapsed_seconds": round(time.monotonic() - start, 3),
                "store_backend": type(self.store).__name__,
                "graphrag_active": self.graphrag.using_graphrag,
            },
        )
