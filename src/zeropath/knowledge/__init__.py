"""
Phase 8: Knowledge Graph + Memory System (GraphRAG).

Institutional memory layer that compounds across runs. Stores validated
exploits, ingests external threat intel (DeFiHackLabs / Rekt / Immunefi),
runs similarity + temporal queries, and feeds prediction accuracy back to
Phases 2 / 3 / 7.

Public API::

    from zeropath.knowledge import KnowledgeGraphOrchestrator, IntelSource

    kg = KnowledgeGraphOrchestrator()
    kg.ingest_validation_report(validation_report)
    kg.ingest_threat_intel(IntelSource.DEFIHACKLABS, defihacklabs_entries)
    boost, matches = kg.lookup_historical_grounding(hypothesis)
    print(kg.report(protocol_name="MyProtocol"))
"""

from zeropath.knowledge.feedback_loop import FeedbackLoopTracker
from zeropath.knowledge.graphrag import (
    GraphRAGAdapter,
    GraphSummary,
    LocalSummariser,
)
from zeropath.knowledge.ingestion import IngestionEngine
from zeropath.knowledge.knowledge import KnowledgeGraphOrchestrator
from zeropath.knowledge.models import (
    AccuracyMetric,
    ExploitRecord,
    ExternalIncidentRecord,
    InferenceKind,
    InferenceRecord,
    IntelSource,
    KGEdge,
    KGNode,
    KnowledgeReport,
    SimilarityHit,
    UpgradeEventRecord,
    ValidationOutcome,
)
from zeropath.knowledge.schema import (
    SCHEMA_QUERIES,
    NodeLabel,
    RelationshipType,
)
from zeropath.knowledge.similarity import (
    SimilarityEngine,
    cosine,
    jaccard,
)
from zeropath.knowledge.store import (
    InMemoryKGStore,
    KGStore,
    Neo4jKGStore,
)
from zeropath.knowledge.temporal import (
    TemporalAnalyzer,
    TemporalSummary,
    UpgradeExposure,
)
from zeropath.knowledge.threat_intel import (
    DeFiHackLabsParser,
    ImmunefiParser,
    ParseStats,
    RektNewsParser,
    ThreatIntelIngestor,
    normalise_attack_class,
)

__all__ = [
    # Orchestrator
    "KnowledgeGraphOrchestrator",
    # Components
    "IngestionEngine",
    "ThreatIntelIngestor",
    "DeFiHackLabsParser", "RektNewsParser", "ImmunefiParser", "ParseStats",
    "SimilarityEngine", "jaccard", "cosine",
    "TemporalAnalyzer", "TemporalSummary", "UpgradeExposure",
    "FeedbackLoopTracker",
    "GraphRAGAdapter", "GraphSummary", "LocalSummariser",
    "InMemoryKGStore", "Neo4jKGStore", "KGStore",
    "normalise_attack_class",
    # Schema
    "NodeLabel", "RelationshipType", "SCHEMA_QUERIES",
    # Models
    "ExploitRecord", "ExternalIncidentRecord", "InferenceRecord",
    "UpgradeEventRecord", "AccuracyMetric", "SimilarityHit",
    "KGNode", "KGEdge", "KnowledgeReport",
    "IntelSource", "InferenceKind", "ValidationOutcome",
]
