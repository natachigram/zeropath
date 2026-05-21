"""
FeedbackLoopTracker — Phase 8.

Spec (phases.md, PHASE 8 critical additions, "Feedback loop quality measurement"):
    "Track prediction accuracy over time:
       - invariants inferred in Phase 2 → were they actually violated later?
       - attack hypotheses in Phase 3 → were they validated in Phase 6?
       - RL-discovered sequences → which generalized to new protocols?

     This measurement loop is what separates a memory system from a database."

The tracker:

  1. Accepts inference records as they happen (Phase 2 / 3 / 7 emit them).
  2. Reconciles them against later validation outcomes (Phase 6 outputs).
  3. Computes accuracy rollups per attack class and per protocol type,
     plus a global precision/recall-proxy headline.

Persistence: each :class:`InferenceRecord` becomes an ``Inference`` node in
the KG, with edges to the :class:`ValidatedExploit` that resolved it
(positive) or a marker property for invalidated/duplicate outcomes.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable, Optional

from zeropath.knowledge.models import (
    AccuracyMetric,
    InferenceKind,
    InferenceRecord,
    KGEdge,
    KGNode,
    ValidationOutcome,
    _utc_now,
)
from zeropath.knowledge.schema import NodeLabel, RelationshipType
from zeropath.knowledge.store import KGStore

logger = logging.getLogger(__name__)


class FeedbackLoopTracker:
    """
    Inference accounting layer on top of the KG.

    Parameters
    ----------
    store : KGStore
        Underlying KG backend; the tracker upserts ``Inference`` nodes and
        keeps an in-memory index for fast accuracy queries.
    """

    def __init__(self, store: KGStore) -> None:
        self.store = store
        # Index: inference_id → InferenceRecord (mirrors the KG, but typed).
        self._records: dict[str, InferenceRecord] = {}

    # ------------------------------------------------------------------
    # Recording predictions
    # ------------------------------------------------------------------

    def record_inference(self, record: InferenceRecord) -> InferenceRecord:
        """Persist a new inference as ``InferenceOutcome.PENDING``."""
        self._records[record.id] = record
        self._upsert_node(record)
        return record

    def record_invariant_inference(
        self,
        *,
        invariant_id: str,
        protocol_name: str,
        attack_class: str,
        description: str,
        confidence: float,
    ) -> InferenceRecord:
        return self.record_inference(InferenceRecord(
            kind=InferenceKind.INVARIANT,
            protocol_name=protocol_name,
            attack_class=attack_class,
            description=description,
            confidence_at_prediction=confidence,
            source_phase=2,
            source_id=invariant_id,
        ))

    def record_hypothesis_inference(
        self,
        *,
        hypothesis_id: str,
        protocol_name: str,
        attack_class: str,
        description: str,
        confidence: float,
    ) -> InferenceRecord:
        return self.record_inference(InferenceRecord(
            kind=InferenceKind.ATTACK_HYPOTHESIS,
            protocol_name=protocol_name,
            attack_class=attack_class,
            description=description,
            confidence_at_prediction=confidence,
            source_phase=3,
            source_id=hypothesis_id,
        ))

    def record_rl_inference(
        self,
        *,
        sequence_id: str,
        protocol_name: str,
        attack_class: str,
        description: str,
    ) -> InferenceRecord:
        return self.record_inference(InferenceRecord(
            kind=InferenceKind.RL_DISCOVERED,
            protocol_name=protocol_name,
            attack_class=attack_class,
            description=description,
            confidence_at_prediction=0.5,
            source_phase=7,
            source_id=sequence_id,
        ))

    # ------------------------------------------------------------------
    # Resolving outcomes
    # ------------------------------------------------------------------

    def mark_validated(
        self, inference_id: str, *, exploit_id: str
    ) -> Optional[InferenceRecord]:
        record = self._records.get(inference_id)
        if record is None:
            return None
        record.outcome = ValidationOutcome.VALIDATED
        record.resolved_at = _utc_now()
        record.resolution_exploit_id = exploit_id
        self._upsert_node(record)
        self._upsert_edge(
            record.id, exploit_id, RelationshipType.VALIDATED,
        )
        return record

    def mark_invalidated(
        self, inference_id: str, *, reason: str = ""
    ) -> Optional[InferenceRecord]:
        record = self._records.get(inference_id)
        if record is None:
            return None
        record.outcome = ValidationOutcome.INVALIDATED
        record.resolved_at = _utc_now()
        self._upsert_node(record, extra_props={"invalidation_reason": reason})
        return record

    def mark_duplicate(
        self, inference_id: str, *, duplicate_of: str
    ) -> Optional[InferenceRecord]:
        record = self._records.get(inference_id)
        if record is None:
            return None
        record.outcome = ValidationOutcome.DUPLICATE
        record.resolved_at = _utc_now()
        self._upsert_node(record, extra_props={"duplicate_of": duplicate_of})
        return record

    def reconcile(
        self,
        *,
        source_id: str,
        outcome: ValidationOutcome,
        exploit_id: Optional[str] = None,
        reason: str = "",
    ) -> Optional[InferenceRecord]:
        """
        Convenience: find an inference by its source_id (the Phase 2/3/7
        artefact ID) and update its outcome. Returns ``None`` when no
        inference references the source.
        """
        match = next(
            (r for r in self._records.values() if r.source_id == source_id), None,
        )
        if match is None:
            return None
        if outcome == ValidationOutcome.VALIDATED:
            return self.mark_validated(match.id, exploit_id=exploit_id or "")
        if outcome == ValidationOutcome.INVALIDATED:
            return self.mark_invalidated(match.id, reason=reason)
        if outcome == ValidationOutcome.DUPLICATE:
            return self.mark_duplicate(match.id, duplicate_of=exploit_id or "")
        return match

    # ------------------------------------------------------------------
    # Accuracy rollups
    # ------------------------------------------------------------------

    def accuracy_by_attack_class(self) -> list[AccuracyMetric]:
        return self._accuracy_grouped(lambda r: r.attack_class or "unknown",
                                      dimension="attack_class")

    def accuracy_by_protocol(self) -> list[AccuracyMetric]:
        return self._accuracy_grouped(lambda r: r.protocol_name or "unknown",
                                      dimension="protocol")

    def overall_accuracy(self) -> AccuracyMetric:
        metric = AccuracyMetric(dimension="overall", key="overall")
        for r in self._records.values():
            self._tally(metric, r)
        return metric

    def all_metrics(self) -> list[AccuracyMetric]:
        return (
            [self.overall_accuracy()]
            + self.accuracy_by_attack_class()
            + self.accuracy_by_protocol()
        )

    # ------------------------------------------------------------------
    # Indexing helpers
    # ------------------------------------------------------------------

    def by_kind(self, kind: InferenceKind) -> list[InferenceRecord]:
        return [r for r in self._records.values() if r.kind == kind]

    def pending(self) -> list[InferenceRecord]:
        return [r for r in self._records.values()
                if r.outcome == ValidationOutcome.PENDING]

    def __len__(self) -> int:
        return len(self._records)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _accuracy_grouped(self, key_fn, *, dimension: str) -> list[AccuracyMetric]:
        buckets: dict[str, AccuracyMetric] = {}
        for record in self._records.values():
            key = key_fn(record)
            metric = buckets.setdefault(
                key, AccuracyMetric(dimension=dimension, key=key)
            )
            self._tally(metric, record)
        return list(buckets.values())

    @staticmethod
    def _tally(metric: AccuracyMetric, record: InferenceRecord) -> None:
        metric.total += 1
        if record.outcome == ValidationOutcome.VALIDATED:
            metric.validated += 1
        elif record.outcome == ValidationOutcome.INVALIDATED:
            metric.invalidated += 1
        elif record.outcome == ValidationOutcome.DUPLICATE:
            metric.duplicate += 1
        else:
            metric.pending += 1

    def _upsert_node(
        self,
        record: InferenceRecord,
        *,
        extra_props: Optional[dict] = None,
    ) -> None:
        props = record.model_dump(mode="json")
        if extra_props:
            props.update(extra_props)
        props["id"] = record.id
        self.store.upsert_node(KGNode(
            id=record.id,
            label=NodeLabel.INFERENCE,
            properties=props,
        ))

    def _upsert_edge(self, from_id: str, to_id: str, rel: RelationshipType) -> None:
        self.store.upsert_edge(KGEdge(
            from_id=from_id, to_id=to_id, type=rel,
        ))
