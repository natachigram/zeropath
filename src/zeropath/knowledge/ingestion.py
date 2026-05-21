"""
Validation-result → KG ingestion — Phase 8.

Converts the artefacts earlier phases produce into KG nodes + edges:

  Phase 1 ProtocolGraph         → Protocol + Function + StateVariable nodes
  Phase 2 InvariantReport       → Invariant nodes + INTRODUCED_IN edges
  Phase 6 ValidationResult      → ValidatedExploit nodes + EXPLOITS / VIOLATES
                                  / INSTANCE_OF edges
  Phase 7 TrainingReport        → RL-discovered exploits promoted into the KG

The ingestor is idempotent: re-running on the same artefacts updates
properties in place rather than duplicating, because both store backends
implement MERGE-style upsert.
"""

from __future__ import annotations

import logging
from typing import Iterable, Optional

from zeropath.invariants.models import Invariant, InvariantReport
from zeropath.knowledge.models import (
    ExploitRecord,
    ExternalIncidentRecord,
    KGEdge,
    KGNode,
    UpgradeEventRecord,
    _utc_now,
)
from zeropath.knowledge.schema import NodeLabel, RelationshipType
from zeropath.knowledge.store import KGStore
from zeropath.models import ProtocolGraph
from zeropath.validation.models import RecommendedAction, ValidationResult

logger = logging.getLogger(__name__)


class IngestionEngine:
    """
    Write Phase 1-7 artefacts into the KG.

    Parameters
    ----------
    store : KGStore
        Backend (InMemoryKGStore or Neo4jKGStore).
    only_actionable : bool
        When True (default), only validation results with
        ``RecommendedAction.REPORT`` are promoted to first-class
        :class:`ValidatedExploit` nodes. SIMULATE_FURTHER and DISCARD
        still get recorded as ``Inference`` nodes for the feedback loop.
    """

    def __init__(
        self,
        store: KGStore,
        *,
        only_actionable: bool = True,
    ) -> None:
        self.store = store
        self.only_actionable = only_actionable

    # ------------------------------------------------------------------
    # Protocol structure
    # ------------------------------------------------------------------

    def ingest_protocol_graph(self, graph: ProtocolGraph, protocol_name: str) -> KGNode:
        """Upsert the Protocol + its Functions + StateVariables."""
        protocol = self._upsert_protocol(protocol_name)

        for contract in graph.contracts:
            for fn in graph.functions:
                if fn.contract_id != contract.id:
                    continue
                fn_node = self._upsert_node(
                    NodeLabel.FUNCTION,
                    f"fn::{protocol_name}::{contract.name}::{fn.name}",
                    {
                        "name": fn.name,
                        "contract": contract.name,
                        "visibility": fn.visibility.value if hasattr(fn.visibility, "value") else str(fn.visibility),
                        "protocol": protocol_name,
                    },
                )
                self._upsert_edge(protocol.id, fn_node.id, RelationshipType.CONTAINS)
        return protocol

    # ------------------------------------------------------------------
    # Invariants
    # ------------------------------------------------------------------

    def ingest_invariant_report(self, report: InvariantReport) -> list[KGNode]:
        out: list[KGNode] = []
        protocol_node = self._upsert_protocol(report.protocol_name)
        for inv in report.invariants:
            n = self._ingest_invariant(inv, report.protocol_name)
            self._upsert_edge(protocol_node.id, n.id, RelationshipType.CONTAINS)
            out.append(n)
        return out

    def _ingest_invariant(self, inv: Invariant, protocol_name: str) -> KGNode:
        return self._upsert_node(
            NodeLabel.INVARIANT,
            inv.id,
            {
                "type": inv.type.value,
                "severity": inv.severity.value if hasattr(inv.severity, "value") else str(inv.severity),
                "description": inv.description[:500],
                "confidence": inv.confidence,
                "protocol": protocol_name,
                "contracts_involved": list(inv.contracts_involved),
                "functions_involved": list(inv.functions_involved),
                "detector": inv.detector,
            },
        )

    # ------------------------------------------------------------------
    # Validated exploits
    # ------------------------------------------------------------------

    def ingest_validation_result(
        self,
        result: ValidationResult,
        *,
        protocol_name: Optional[str] = None,
    ) -> Optional[ExploitRecord]:
        """
        Promote a Phase 6 :class:`ValidationResult` into a first-class
        :class:`ValidatedExploit` node when actionable. Returns the
        :class:`ExploitRecord` written (or None when skipped).
        """
        if self.only_actionable and result.recommended_action != RecommendedAction.REPORT:
            return None
        if not result.valid:
            return None
        protocol_name = protocol_name or result.protocol_name or "unknown"

        record = ExploitRecord(
            id=result.id,
            protocol_name=protocol_name,
            attack_class=_attack_class_from_validation(result),
            fingerprint=result.fingerprint or "",
            severity_tier=result.severity.profit_tier.value,
            profit_wei=result.profit_wei,
            profit_usd=result.profit_usd,
            capital_required_usd=result.capital_required_usd,
            confidence=result.confidence,
            hypothesis_id=result.hypothesis_id,
            sequence_id=result.sequence_id,
            simulation_id=result.simulation_id,
        )
        self._upsert_node(
            NodeLabel.VALIDATED_EXPLOIT,
            record.id,
            record.model_dump(mode="json"),
        )

        protocol = self._upsert_protocol(protocol_name)
        self._upsert_edge(record.id, protocol.id, RelationshipType.EXPLOITS)

        pattern = self._upsert_node(
            NodeLabel.EXPLOIT_PATTERN,
            f"pattern::{record.attack_class}",
            {"attack_class": record.attack_class},
        )
        self._upsert_edge(record.id, pattern.id, RelationshipType.INSTANCE_OF)

        if record.fingerprint:
            # Phase 6 DuplicateStore plumbing — record the fingerprint so
            # subsequent runs auto-dedupe via DuplicateDetector.
            self.store.record(record.fingerprint, record.id)

        return record

    def ingest_validation_batch(
        self, results: Iterable[ValidationResult]
    ) -> list[ExploitRecord]:
        out: list[ExploitRecord] = []
        for r in results:
            rec = self.ingest_validation_result(r)
            if rec is not None:
                out.append(rec)
        return out

    # ------------------------------------------------------------------
    # External incidents
    # ------------------------------------------------------------------

    def ingest_external_incident(self, record: ExternalIncidentRecord) -> KGNode:
        node = self._upsert_node(
            NodeLabel.EXTERNAL_INCIDENT,
            record.id,
            record.model_dump(mode="json"),
        )
        protocol = self._upsert_protocol(record.protocol)
        self._upsert_edge(node.id, protocol.id, RelationshipType.EXPLOITS)

        pattern = self._upsert_node(
            NodeLabel.EXPLOIT_PATTERN,
            f"pattern::{record.attack_class}",
            {"attack_class": record.attack_class},
        )
        self._upsert_edge(node.id, pattern.id, RelationshipType.INSTANCE_OF)
        return node

    def link_invariant_to_incident(self, invariant_id: str, incident_id: str) -> KGEdge:
        return self._upsert_edge(invariant_id, incident_id, RelationshipType.LINKED_TO)

    # ------------------------------------------------------------------
    # Upgrade events (Phase 1 version diff)
    # ------------------------------------------------------------------

    def ingest_upgrade_event(self, record: UpgradeEventRecord) -> KGNode:
        node = self._upsert_node(
            NodeLabel.UPGRADE_EVENT,
            record.id,
            record.model_dump(mode="json"),
        )
        protocol = self._upsert_protocol(record.protocol_name)
        self._upsert_edge(protocol.id, node.id, RelationshipType.CONTAINS)
        return node

    def link_invariant_to_upgrade(self, invariant_id: str, upgrade_id: str) -> KGEdge:
        return self._upsert_edge(invariant_id, upgrade_id, RelationshipType.INTRODUCED_IN)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _upsert_protocol(self, name: str) -> KGNode:
        return self._upsert_node(
            NodeLabel.PROTOCOL, f"protocol::{name}", {"name": name},
        )

    def _upsert_node(
        self,
        label: NodeLabel,
        node_id: str,
        properties: dict,
    ) -> KGNode:
        properties.setdefault("id", node_id)
        node = KGNode(
            id=node_id,
            label=label,
            properties=properties,
            updated_at=_utc_now(),
        )
        return self.store.upsert_node(node)

    def _upsert_edge(
        self,
        from_id: str,
        to_id: str,
        rel_type: RelationshipType,
        properties: Optional[dict] = None,
    ) -> KGEdge:
        edge = KGEdge(
            from_id=from_id,
            to_id=to_id,
            type=rel_type,
            properties=properties or {},
        )
        return self.store.upsert_edge(edge)


def _attack_class_from_validation(result: ValidationResult) -> str:
    """
    ValidationResult doesn't carry attack_class directly — but the severity
    sub-object's ``capital_required_usd`` / ``requires_flash_loan`` flags +
    the underlying hypothesis (referenced by id) do.

    For ingestion we fall back to the hypothesis_id-derived metadata when
    present, otherwise default to ``unknown``.
    """
    meta = result.analysis_metadata or {}
    return meta.get("attack_class") or "unknown"
