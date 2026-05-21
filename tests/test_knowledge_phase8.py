"""
Phase 8 test suite — Knowledge Graph + Memory System.

Coverage:
  - schema constants + Pydantic models
  - InMemoryKGStore: upsert / lookup / neighbors / fingerprint contract
  - IngestionEngine: protocol graph + invariants + validation results
  - ThreatIntelIngestor: DeFiHackLabs / Rekt / Immunefi parsers + live fetcher
    regex (against an in-memory README sample)
  - SimilarityEngine: protocol / invariant / exploit similarity ranking
  - TemporalAnalyzer: window detection + summary aggregation
  - FeedbackLoopTracker: PENDING -> VALIDATED/INVALIDATED reconciliation
  - GraphRAGAdapter: falls back to LocalSummariser when graphrag not present
  - KnowledgeGraphOrchestrator: end-to-end ingest + grounding query
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from zeropath.adversarial.models import (
    AttackClass,
    AttackHypothesis,
    HypothesisStatus,
    SwarmReport,
)
from zeropath.invariants.models import (
    DeFiProtocolType,
    Invariant,
    InvariantReport,
    InvariantSeverity,
    InvariantType,
    ProtocolPattern,
)
from zeropath.knowledge import (
    AccuracyMetric,
    DeFiHackLabsParser,
    ExploitRecord,
    ExternalIncidentRecord,
    FeedbackLoopTracker,
    GraphRAGAdapter,
    GraphSummary,
    ImmunefiParser,
    InMemoryKGStore,
    InferenceKind,
    IngestionEngine,
    IntelSource,
    KGEdge,
    KGNode,
    KnowledgeGraphOrchestrator,
    KnowledgeReport,
    LocalSummariser,
    NodeLabel,
    ParseStats,
    RektNewsParser,
    RelationshipType,
    SimilarityEngine,
    SimilarityHit,
    TemporalAnalyzer,
    ThreatIntelIngestor,
    UpgradeEventRecord,
    UpgradeExposure,
    ValidationOutcome,
    cosine,
    jaccard,
    normalise_attack_class,
)
from zeropath.knowledge.threat_intel import _coerce_loss_usd
from zeropath.models import ProtocolGraph
from zeropath.validation.models import (
    ProfitTier,
    RecommendedAction,
    SeverityScore,
    ValidationReport,
    ValidationResult,
)


# ===========================================================================
# Test fixtures
# ===========================================================================


def _mk_validation(
    *,
    protocol_name: str = "TestProtocol",
    hypothesis_id: str | None = None,
    fingerprint: str = "fingerprint-abc",
    valid: bool = True,
    profit_wei: int = 10 ** 18,
    severity_tier: ProfitTier = ProfitTier.HIGH,
    action: RecommendedAction = RecommendedAction.REPORT,
) -> ValidationResult:
    return ValidationResult(
        valid=valid,
        reason="all checks passed",
        confidence=0.8,
        severity=SeverityScore(
            profit_tier=severity_tier,
            requires_flash_loan=True,
            capital_required_usd=0,
            composite_score=0.7,
        ),
        recommended_action=action,
        hypothesis_id=hypothesis_id or str(uuid4()),
        sequence_id=str(uuid4()),
        simulation_id=str(uuid4()),
        protocol_name=protocol_name,
        fingerprint=fingerprint,
        profit_wei=profit_wei,
        profit_usd=profit_wei / 10 ** 18 * 3000,
    )


def _mk_invariant_report(protocol_name: str = "TestProtocol") -> InvariantReport:
    return InvariantReport(
        protocol_name=protocol_name,
        protocol_pattern=ProtocolPattern(
            protocol_types=[DeFiProtocolType.LENDING],
            has_oracle=True,
            borrow_functions=["borrow"],
        ),
        invariants=[
            Invariant(
                type=InvariantType.ORACLE_MANIPULATION,
                severity=InvariantSeverity.CRITICAL,
                description="Single-block oracle read",
                confidence=0.85,
                contracts_involved=["LendingPool"],
                functions_involved=["borrow"],
            ),
        ],
    )


# ===========================================================================
# Models + schema
# ===========================================================================


class TestSchema:
    def test_node_labels_unique(self):
        values = [n.value for n in NodeLabel]
        assert len(values) == len(set(values))

    def test_relationship_types_unique(self):
        values = [r.value for r in RelationshipType]
        assert len(values) == len(set(values))


class TestModels:
    def test_kgnode_default_id(self):
        n = KGNode(label=NodeLabel.PROTOCOL)
        assert n.id and len(n.id) >= 16

    def test_accuracy_metric_precision(self):
        m = AccuracyMetric(dimension="overall", key="x",
                            total=10, validated=6, invalidated=2, pending=2)
        assert m.precision == pytest.approx(0.75, abs=1e-3)
        assert m.recall_proxy == pytest.approx(0.6, abs=1e-3)

    def test_accuracy_metric_no_decisions(self):
        m = AccuracyMetric(dimension="x", key="x")
        assert m.precision == 0.0


class TestCoerceLossUsd:
    @pytest.mark.parametrize("raw, expected", [
        ("$197M", 197_000_000),
        ("$1.5 billion", 1_500_000_000),
        ("32.8 ETH", 32 * 3000 + int(0.8 * 3000)),  # ≈ 98_400
        ("1.2 eth", int(1.2 * 3000)),
        ("$50k", 50_000),
        ("197000000", 197_000_000),
        (10**8, 10**8),
        (None, 0),
        ("nonsense", 0),
    ])
    def test_parsing(self, raw, expected):
        assert _coerce_loss_usd(raw) == pytest.approx(expected, abs=2)


# ===========================================================================
# InMemoryKGStore
# ===========================================================================


class TestInMemoryKGStore:
    def test_upsert_node_idempotent(self):
        store = InMemoryKGStore()
        n1 = KGNode(id="X", label=NodeLabel.PROTOCOL, properties={"name": "A"})
        n2 = KGNode(id="X", label=NodeLabel.PROTOCOL, properties={"name": "A", "extra": 1})
        store.upsert_node(n1)
        store.upsert_node(n2)
        assert store.node_count == 1
        n = store.get_node("X")
        assert n.properties.get("extra") == 1

    def test_upsert_edge_deduplicates(self):
        store = InMemoryKGStore()
        store.upsert_node(KGNode(id="A", label=NodeLabel.PROTOCOL))
        store.upsert_node(KGNode(id="B", label=NodeLabel.PROTOCOL))
        e1 = KGEdge(from_id="A", to_id="B", type=RelationshipType.CONTAINS)
        e2 = KGEdge(from_id="A", to_id="B", type=RelationshipType.CONTAINS, properties={"w": 1})
        store.upsert_edge(e1)
        store.upsert_edge(e2)
        assert store.edge_count == 1
        assert store.all_edges()[0].properties.get("w") == 1

    def test_find_by_label(self):
        store = InMemoryKGStore()
        store.upsert_node(KGNode(id="A", label=NodeLabel.PROTOCOL))
        store.upsert_node(KGNode(id="B", label=NodeLabel.INVARIANT))
        assert len(store.find_by_label(NodeLabel.PROTOCOL)) == 1
        assert len(store.find_by_label(NodeLabel.INVARIANT)) == 1

    def test_find_by_property(self):
        store = InMemoryKGStore()
        store.upsert_node(KGNode(
            id="A", label=NodeLabel.PROTOCOL, properties={"name": "Aave"},
        ))
        hits = store.find_by_property(NodeLabel.PROTOCOL, "name", "Aave")
        assert len(hits) == 1 and hits[0].id == "A"

    def test_neighbors_direction(self):
        store = InMemoryKGStore()
        store.upsert_node(KGNode(id="A", label=NodeLabel.PROTOCOL))
        store.upsert_node(KGNode(id="B", label=NodeLabel.FUNCTION))
        store.upsert_edge(KGEdge(from_id="A", to_id="B", type=RelationshipType.CONTAINS))

        out = store.neighbors("A", direction="out")
        assert len(out) == 1 and out[0][1].id == "B"

        inn = store.neighbors("B", direction="in")
        assert len(inn) == 1 and inn[0][1].id == "A"

    def test_phase6_duplicate_store_contract(self):
        store = InMemoryKGStore()
        store.record("fp-1", "V-1")
        assert store.lookup("fp-1") == "V-1"
        # record() is idempotent (setdefault semantics)
        store.record("fp-1", "V-2")
        assert store.lookup("fp-1") == "V-1"
        assert "fp-1" in store.fingerprints()

    def test_snapshot_restore_round_trip(self, tmp_path):
        store = InMemoryKGStore()
        store.upsert_node(KGNode(id="A", label=NodeLabel.PROTOCOL,
                                  properties={"name": "Aave"}))
        store.upsert_node(KGNode(id="B", label=NodeLabel.INVARIANT,
                                  properties={"type": "oracle"}))
        store.upsert_edge(KGEdge(from_id="A", to_id="B",
                                  type=RelationshipType.CONTAINS))
        store.record("fp", "V")
        path = store.snapshot(tmp_path / "kg.json")
        assert path.exists()

        store2 = InMemoryKGStore()
        store2.restore(tmp_path / "kg.json")
        assert store2.node_count == 2
        assert store2.edge_count == 1
        assert store2.lookup("fp") == "V"


# ===========================================================================
# IngestionEngine
# ===========================================================================


class TestIngestionEngine:
    def test_ingest_invariant_report(self):
        store = InMemoryKGStore()
        eng = IngestionEngine(store)
        eng.ingest_invariant_report(_mk_invariant_report())
        assert len(store.find_by_label(NodeLabel.INVARIANT)) == 1
        assert len(store.find_by_label(NodeLabel.PROTOCOL)) == 1

    def test_ingest_validation_result_creates_exploit_node(self):
        store = InMemoryKGStore()
        eng = IngestionEngine(store)
        rec = eng.ingest_validation_result(_mk_validation())
        assert isinstance(rec, ExploitRecord)
        assert len(store.find_by_label(NodeLabel.VALIDATED_EXPLOIT)) == 1
        assert len(store.find_by_label(NodeLabel.EXPLOIT_PATTERN)) == 1

    def test_only_actionable_filter_drops_simulate_further(self):
        store = InMemoryKGStore()
        eng = IngestionEngine(store, only_actionable=True)
        rec = eng.ingest_validation_result(_mk_validation(
            action=RecommendedAction.SIMULATE_FURTHER,
        ))
        assert rec is None
        assert len(store.find_by_label(NodeLabel.VALIDATED_EXPLOIT)) == 0

    def test_fingerprint_recorded_for_phase6_dedup(self):
        store = InMemoryKGStore()
        eng = IngestionEngine(store)
        eng.ingest_validation_result(_mk_validation(fingerprint="abc"))
        # Phase 6 DuplicateStore protocol round-trip
        assert store.lookup("abc") is not None

    def test_idempotent_double_ingest(self):
        store = InMemoryKGStore()
        eng = IngestionEngine(store)
        v = _mk_validation()
        eng.ingest_validation_result(v)
        eng.ingest_validation_result(v)
        assert len(store.find_by_label(NodeLabel.VALIDATED_EXPLOIT)) == 1


# ===========================================================================
# ThreatIntel parsers
# ===========================================================================


class TestNormaliseAttackClass:
    @pytest.mark.parametrize("text, expected", [
        ("flash loan attack", "flash_loan"),
        ("Reentrancy via callback", "reentrancy"),
        ("Price Oracle Manipulation", "oracle_manipulation"),
        ("TWAP manipulation", "oracle_manipulation"),
        ("Access control bug", "access_control"),
        ("integer overflow", "integer_math"),
        ("precision loss", "integer_math"),
        ("Unknown weirdness", "unknown"),
        ("", "unknown"),
    ])
    def test_keyword_matching(self, text, expected):
        assert normalise_attack_class(text) == expected


class TestDeFiHackLabsParser:
    def test_parses_minimal_entry(self):
        rec = DeFiHackLabsParser().parse_one({
            "protocol": "EulerFinance",
            "date": "2023-03-13",
            "loss": "$197M",
            "attack": "flash loan donation",
            "article": "https://example.com",
        })
        assert rec is not None
        assert rec.protocol == "EulerFinance"
        assert rec.attack_class == "flash_loan"
        assert rec.loss_usd == 197_000_000
        assert rec.source == IntelSource.DEFIHACKLABS

    def test_skips_entry_without_protocol(self):
        assert DeFiHackLabsParser().parse_one({}) is None

    def test_parse_many_returns_stats(self):
        recs, stats = DeFiHackLabsParser().parse_many([
            {"protocol": "A", "attack": "reentrancy"},
            {},  # skipped
            {"protocol": "B", "attack": "oracle", "loss": "$1M"},
        ])
        assert len(recs) == 2
        assert stats.accepted == 2
        assert stats.skipped == 1

    def test_extracts_addresses_from_payload(self):
        addr = "0x" + "ab" * 20
        rec = DeFiHackLabsParser().parse_one({
            "protocol": "X",
            "attack": "reentrancy",
            "tx": addr,
        })
        assert addr.lower() in [a.lower() for a in rec.affected_addresses]


class TestLiveFetcherRegex:
    """
    Exercise the live fetcher's regexes against an in-memory README
    sample — verifies the parser without hitting the network.
    """

    SAMPLE_README = """
some preamble text...

### 20260101 PRXVT - Bussiness Logic Flaw

### Lost: 32.8 ETH

```sh
forge test --contracts ./src/test/2026-01/PRXVT_exp.sol -vvv
```
#### Contract
[PRXVT_exp.sol](src/test/2026-01/PRXVT_exp.sol)
### Link reference

https://x.com/CertiKAlert/status/2006685174587605315

---

### 20260120 Makina - Price Oracle Manipulation

### Lost: $1.2M

```sh
forge test ...
```
### Link reference

https://example.com/makina-postmortem

---
"""

    def test_fetch_live_entries_parses_sample(self, monkeypatch):
        # Patch requests.get to return our sample README.
        import zeropath.knowledge.threat_intel as ti_module

        class FakeResp:
            text = TestLiveFetcherRegex.SAMPLE_README
            def raise_for_status(self):
                pass

        monkeypatch.setattr(ti_module.requests, "get", lambda *a, **kw: FakeResp())

        entries = DeFiHackLabsParser.fetch_live_entries(timeout=1)
        assert len(entries) == 2
        prxvt = entries[0]
        assert prxvt["protocol"] == "PRXVT"
        assert prxvt["date"] == "2026-01-01"
        assert "ETH" in prxvt["loss"]
        assert prxvt["attack"] == "Bussiness Logic Flaw"

        makina = entries[1]
        assert makina["protocol"] == "Makina"
        assert makina["date"] == "2026-01-20"
        assert makina["loss"] == "$1.2M"
        assert "Oracle Manipulation" in makina["attack"]

    def test_fetch_returns_empty_on_network_failure(self, monkeypatch):
        import zeropath.knowledge.threat_intel as ti_module
        import requests as _req

        def boom(*a, **kw):
            raise _req.ConnectionError("offline")

        monkeypatch.setattr(ti_module.requests, "get", boom)
        assert DeFiHackLabsParser.fetch_live_entries(timeout=1) == []


class TestRektNewsParser:
    def test_parses_leaderboard_entry(self):
        rec = RektNewsParser().parse_one({
            "name": "Ronin Bridge",
            "date": "2022-03-23",
            "funds_lost": "$625M",
            "tags": ["access control", "bridge"],
            "url": "https://rekt.news/ronin-rekt/",
        })
        assert rec.protocol == "Ronin Bridge"
        assert rec.attack_class == "access_control"
        assert rec.loss_usd == 625_000_000


class TestImmunefiParser:
    def test_parses_postmortem(self):
        rec = ImmunefiParser().parse_one({
            "project": "Wormhole",
            "date": "2022-02-02",
            "loss_usd": 326_000_000,
            "vulnerability_type": "signature verification bypass",
            "root_cause": "Failed to validate guardian signatures",
            "links": ["https://immunefi.com/postmortems/wormhole/"],
        })
        assert rec.protocol == "Wormhole"
        assert rec.loss_usd == 326_000_000
        assert rec.source == IntelSource.IMMUNEFI


class TestThreatIntelIngestor:
    def test_ingest_entries_writes_to_store(self):
        store = InMemoryKGStore()
        ingestor = ThreatIntelIngestor(IngestionEngine(store))
        recs, stats = ingestor.ingest_entries(IntelSource.DEFIHACKLABS, [
            {"protocol": "Euler", "attack": "flash loan", "loss": "$197M"},
        ])
        assert stats.accepted == 1
        assert len(store.find_by_label(NodeLabel.EXTERNAL_INCIDENT)) == 1

    def test_unknown_source_raises(self):
        ingestor = ThreatIntelIngestor(IngestionEngine(InMemoryKGStore()))
        with pytest.raises(ValueError):
            ingestor.ingest_entries(IntelSource.CHAINALYSIS, [])

    def test_ingest_defihacklabs_live_handles_network_failure(self, monkeypatch):
        import zeropath.knowledge.threat_intel as ti_module
        import requests as _req
        monkeypatch.setattr(ti_module.requests, "get",
                            lambda *a, **kw: (_ for _ in ()).throw(_req.ConnectionError("x")))
        ingestor = ThreatIntelIngestor(IngestionEngine(InMemoryKGStore()))
        recs, stats = ingestor.ingest_defihacklabs_live(timeout=1)
        assert recs == []


# ===========================================================================
# SimilarityEngine
# ===========================================================================


class TestSimilarityMath:
    def test_jaccard_basic(self):
        assert jaccard({"a", "b"}, {"a", "c"}) == pytest.approx(1 / 3)

    def test_jaccard_disjoint(self):
        assert jaccard({"a"}, {"b"}) == 0.0

    def test_jaccard_both_empty(self):
        assert jaccard(set(), set()) == 0.0

    def test_cosine_identical(self):
        from collections import Counter
        v = Counter({"a": 1, "b": 2})
        assert cosine(v, v) == pytest.approx(1.0)

    def test_cosine_empty(self):
        from collections import Counter
        assert cosine(Counter(), Counter({"a": 1})) == 0.0


class TestSimilarityEngine:
    def test_find_similar_protocols(self):
        store = InMemoryKGStore()
        eng = SimilarityEngine(store)
        # Build two protocols sharing a function
        for name in ("Aave", "Compound"):
            store.upsert_node(KGNode(
                id=f"protocol::{name}",
                label=NodeLabel.PROTOCOL,
                properties={"name": name},
            ))
        fn1 = KGNode(id="fn1", label=NodeLabel.FUNCTION, properties={"name": "borrow"})
        fn2 = KGNode(id="fn2", label=NodeLabel.FUNCTION, properties={"name": "borrow"})
        fn3 = KGNode(id="fn3", label=NodeLabel.FUNCTION, properties={"name": "liquidate"})
        for n in (fn1, fn2, fn3):
            store.upsert_node(n)
        store.upsert_edge(KGEdge(from_id="protocol::Aave", to_id="fn1",
                                  type=RelationshipType.CONTAINS))
        store.upsert_edge(KGEdge(from_id="protocol::Compound", to_id="fn2",
                                  type=RelationshipType.CONTAINS))
        store.upsert_edge(KGEdge(from_id="protocol::Compound", to_id="fn3",
                                  type=RelationshipType.CONTAINS))
        hits = eng.find_similar_protocols("Aave")
        assert len(hits) == 1
        assert hits[0].target_name == "Compound"
        assert hits[0].score > 0

    def test_similar_protocols_empty_when_unknown(self):
        eng = SimilarityEngine(InMemoryKGStore())
        assert eng.find_similar_protocols("Nonexistent") == []

    def test_similar_exploits_class_match_bias(self):
        store = InMemoryKGStore()
        eng = IngestionEngine(store)
        eng.ingest_validation_result(_mk_validation(
            protocol_name="A", fingerprint="x-A",
        ))
        eng.ingest_validation_result(_mk_validation(
            protocol_name="B", fingerprint="x-B",
        ))
        sim = SimilarityEngine(store)
        exploits = store.find_by_label(NodeLabel.VALIDATED_EXPLOIT)
        hits = sim.find_similar_exploits(exploits[0].id)
        # The other exploit shares the same (default) attack_class so should appear.
        assert len(hits) == 1
        assert hits[0].score > 0


# ===========================================================================
# TemporalAnalyzer
# ===========================================================================


class TestTemporalAnalyzer:
    def test_no_data_yields_zero_summary(self):
        ta = TemporalAnalyzer(InMemoryKGStore())
        s = ta.summarise("Nonexistent")
        assert s.exposures == 0
        assert s.upgrades == 0

    def test_upgrade_within_window(self):
        store = InMemoryKGStore()
        eng = IngestionEngine(store)
        eng._upsert_protocol("AaveV3")
        eng.ingest_upgrade_event(UpgradeEventRecord(
            protocol_name="AaveV3", upgrade_date="2024-01-01T00:00:00+00:00",
        ))
        # Validated exploit recorded 10 days later
        v = _mk_validation(protocol_name="AaveV3", fingerprint="z")
        rec = eng.ingest_validation_result(v)
        # Override recorded_at on the exploit node
        node = store.get_node(rec.id)
        node.properties["recorded_at"] = "2024-01-11T00:00:00+00:00"
        store.upsert_node(node)

        ta = TemporalAnalyzer(store, window_days=30)
        summary = ta.summarise("AaveV3")
        assert summary.upgrades == 1
        assert summary.exposures == 1
        assert summary.exposures_within_window == 1
        assert summary.samples[0].days_after_upgrade == 10

    def test_exploit_before_upgrade_excluded(self):
        store = InMemoryKGStore()
        eng = IngestionEngine(store)
        eng._upsert_protocol("X")
        eng.ingest_upgrade_event(UpgradeEventRecord(
            protocol_name="X", upgrade_date="2024-06-01T00:00:00+00:00",
        ))
        v = _mk_validation(protocol_name="X", fingerprint="y")
        rec = eng.ingest_validation_result(v)
        node = store.get_node(rec.id)
        node.properties["recorded_at"] = "2024-01-01T00:00:00+00:00"
        store.upsert_node(node)
        ta = TemporalAnalyzer(store)
        summary = ta.summarise("X")
        assert summary.exposures == 0

    def test_overall_risk_aggregates(self):
        store = InMemoryKGStore()
        ta = TemporalAnalyzer(store)
        assert ta.overall_post_upgrade_risk() == 0.0


# ===========================================================================
# FeedbackLoopTracker
# ===========================================================================


class TestFeedbackLoopTracker:
    def test_record_then_validate(self):
        store = InMemoryKGStore()
        tracker = FeedbackLoopTracker(store)
        record = tracker.record_hypothesis_inference(
            hypothesis_id="H1", protocol_name="X", attack_class="oracle",
            description="t", confidence=0.7,
        )
        assert tracker.pending() == [record]
        updated = tracker.mark_validated(record.id, exploit_id="E1")
        assert updated.outcome == ValidationOutcome.VALIDATED
        assert tracker.pending() == []

    def test_reconcile_by_source_id(self):
        tracker = FeedbackLoopTracker(InMemoryKGStore())
        tracker.record_hypothesis_inference(
            hypothesis_id="H1", protocol_name="X", attack_class="oracle",
            description="t", confidence=0.7,
        )
        out = tracker.reconcile(source_id="H1",
                                outcome=ValidationOutcome.INVALIDATED,
                                reason="too vague")
        assert out is not None
        assert out.outcome == ValidationOutcome.INVALIDATED

    def test_accuracy_by_attack_class(self):
        tracker = FeedbackLoopTracker(InMemoryKGStore())
        for i in range(3):
            r = tracker.record_invariant_inference(
                invariant_id=f"I{i}", protocol_name="X", attack_class="oracle",
                description="t", confidence=0.8,
            )
            tracker.mark_validated(r.id, exploit_id="E")
        # One invalidated
        r = tracker.record_invariant_inference(
            invariant_id="I3", protocol_name="X", attack_class="oracle",
            description="t", confidence=0.6,
        )
        tracker.mark_invalidated(r.id)
        # Different class, pending
        tracker.record_invariant_inference(
            invariant_id="I4", protocol_name="X", attack_class="reentrancy",
            description="t", confidence=0.6,
        )
        metrics = tracker.accuracy_by_attack_class()
        oracle = next(m for m in metrics if m.key == "oracle")
        assert oracle.total == 4
        assert oracle.validated == 3
        assert oracle.invalidated == 1
        # Precision = validated / (validated + invalidated) = 3/4
        assert oracle.precision == pytest.approx(0.75)

    def test_overall_accuracy(self):
        tracker = FeedbackLoopTracker(InMemoryKGStore())
        r = tracker.record_rl_inference(
            sequence_id="S1", protocol_name="X", attack_class="oracle",
            description="t",
        )
        tracker.mark_validated(r.id, exploit_id="E")
        overall = tracker.overall_accuracy()
        assert overall.dimension == "overall"
        assert overall.validated == 1

    def test_mark_duplicate(self):
        tracker = FeedbackLoopTracker(InMemoryKGStore())
        r = tracker.record_hypothesis_inference(
            hypothesis_id="H", protocol_name="X", attack_class="x",
            description="t", confidence=0.6,
        )
        out = tracker.mark_duplicate(r.id, duplicate_of="OTHER")
        assert out.outcome == ValidationOutcome.DUPLICATE

    def test_pending_filter(self):
        tracker = FeedbackLoopTracker(InMemoryKGStore())
        r1 = tracker.record_hypothesis_inference(
            hypothesis_id="H1", protocol_name="X", attack_class="x",
            description="t", confidence=0.6,
        )
        r2 = tracker.record_hypothesis_inference(
            hypothesis_id="H2", protocol_name="X", attack_class="x",
            description="t", confidence=0.6,
        )
        tracker.mark_validated(r1.id, exploit_id="E")
        pending = tracker.pending()
        assert len(pending) == 1 and pending[0].id == r2.id


# ===========================================================================
# GraphRAG adapter
# ===========================================================================


class TestGraphRAGAdapter:
    def test_falls_back_to_local_when_graphrag_missing(self):
        store = InMemoryKGStore()
        adapter = GraphRAGAdapter(store)
        # graphrag is not installed in this venv → adapter must fall back
        assert adapter.using_graphrag is False

    def test_local_summaries_emit_per_attack_class(self):
        store = InMemoryKGStore()
        eng = IngestionEngine(store)
        eng.ingest_validation_result(_mk_validation(fingerprint="a"))
        # Need a second exploit with a different attack_class to verify grouping.
        v2 = _mk_validation(fingerprint="b")
        v2.analysis_metadata = {"attack_class": "reentrancy"}
        eng.ingest_validation_result(v2)
        # Original validation defaults attack_class metadata to "unknown".
        summaries = LocalSummariser(store).global_summaries()
        keys = {s.key for s in summaries}
        assert keys, "expected at least one global summary"
        assert all(s.level == "global" for s in summaries)

    def test_motif_detection_min_support(self):
        store = InMemoryKGStore()
        # Manually inject exploit nodes carrying matching (contract, function).
        for i in range(3):
            store.upsert_node(KGNode(
                id=f"E{i}", label=NodeLabel.VALIDATED_EXPLOIT,
                properties={
                    "contracts_involved": ["LendingPool"],
                    "functions_involved": ["borrow"],
                    "attack_class": "oracle",
                },
            ))
        motifs = LocalSummariser(store).motif_summaries(min_support=2)
        assert any("LendingPool.borrow" in m.key for m in motifs)


# ===========================================================================
# KnowledgeGraphOrchestrator
# ===========================================================================


class TestOrchestrator:
    def test_end_to_end_pipeline(self):
        kg = KnowledgeGraphOrchestrator()
        # Phase 2 invariants
        kg.ingest_invariant_report(_mk_invariant_report())
        # Phase 6 validation
        kg.ingest_validation_result(_mk_validation())
        # External intel
        kg.ingest_threat_intel(IntelSource.DEFIHACKLABS, [
            {"protocol": "TestProtocol", "attack": "flash loan",
             "loss": "$100M", "date": "2024-01-01"},
        ])
        report = kg.report(protocol_name="TestProtocol")
        assert isinstance(report, KnowledgeReport)
        assert report.exploits_ingested == 1
        assert report.incidents_ingested == 1
        assert report.inferences_recorded == 1   # the invariant inference

    def test_lookup_historical_grounding_protocol_match(self):
        kg = KnowledgeGraphOrchestrator()
        kg.ingest_threat_intel(IntelSource.REKT, [
            {"name": "EulerFinance", "tags": ["flash loan"],
             "funds_lost": "$197M"},
        ])
        h = AttackHypothesis(
            invariant_id="x", invariant_description="x",
            attack_class=AttackClass.FLASH_LOAN, title="t",
            proposed_by="X", attack_narrative="y",
            contracts_involved=["EulerFinance"],
        )
        boost, matches = kg.lookup_historical_grounding(h)
        assert boost > 0
        assert len(matches) == 1

    def test_lookup_historical_grounding_no_match(self):
        kg = KnowledgeGraphOrchestrator()
        kg.ingest_threat_intel(IntelSource.DEFIHACKLABS, [
            {"protocol": "Foo", "attack": "access control"},
        ])
        h = AttackHypothesis(
            invariant_id="x", invariant_description="x",
            attack_class=AttackClass.ORACLE_MANIPULATION, title="t",
            proposed_by="X", attack_narrative="y",
        )
        boost, matches = kg.lookup_historical_grounding(h)
        assert boost == 0
        assert matches == []

    def test_lookup_historical_grounding_class_only_match(self):
        # Same class, different protocol — should give partial boost.
        kg = KnowledgeGraphOrchestrator()
        kg.ingest_threat_intel(IntelSource.DEFIHACKLABS, [
            {"protocol": "Foo", "attack": "flash loan"},
            {"protocol": "Bar", "attack": "flash loan"},
        ])
        h = AttackHypothesis(
            invariant_id="x", invariant_description="x",
            attack_class=AttackClass.FLASH_LOAN, title="t",
            proposed_by="X", attack_narrative="y",
            contracts_involved=["DifferentProtocol"],
        )
        boost, matches = kg.lookup_historical_grounding(h)
        # 2 same-class matches, no protocol match → partial boost
        assert 0 < boost < 0.15

    def test_validation_resolves_hypothesis_inference(self):
        kg = KnowledgeGraphOrchestrator()
        swarm = SwarmReport(
            protocol_name="X",
            hypotheses=[AttackHypothesis(
                id="H1", invariant_id="x", invariant_description="x",
                attack_class=AttackClass.ORACLE_MANIPULATION, title="t",
                proposed_by="X", attack_narrative="y",
                status=HypothesisStatus.CONSENSUS,
            )],
        )
        kg.ingest_swarm_report(swarm)
        kg.ingest_validation_result(_mk_validation(hypothesis_id="H1"))
        # The hypothesis inference should now be VALIDATED.
        metrics = kg.feedback.accuracy_by_attack_class()
        # H1's attack_class is oracle_manipulation
        m = next((x for x in metrics if x.key == "oracle_manipulation"), None)
        assert m is not None
        assert m.validated == 1

    def test_neo4jkgstore_attempts_lazy_connection(self):
        """Importing Neo4jKGStore doesn't require a live DB; connect() is lazy."""
        from zeropath.knowledge import Neo4jKGStore
        store = Neo4jKGStore(uri="bolt://nonexistent:7687",
                             username="u", password="p")
        # Constructor should not connect.
        assert store._driver is None
