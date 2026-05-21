"""
KG storage backends — Phase 8.

Two implementations behind the same protocol:

  * :class:`InMemoryKGStore` — default, zero-deps. Used in tests, CI, and
    short-lived runs. Persists to a JSON file via ``snapshot`` / ``restore``.
  * :class:`Neo4jKGStore` — wraps the existing Phase 1 ``neo4j`` driver
    dependency. Lazily connects on first use so importing the package
    doesn't require a live Neo4j.

Both stores expose the same query surface (``upsert_node``, ``upsert_edge``,
``find_by_label``, ``neighbors``, ``lookup_by_fingerprint``) so the rest of
the KG package never has to branch on backend.

Phase 6 :class:`DuplicateStore` compatibility
---------------------------------------------
Both stores expose ``lookup(fingerprint) -> validation_id | None`` and
``record(fingerprint, validation_id)``. That's exactly the protocol the
Phase 6 :class:`DuplicateDetector` consumes, so plugging the KG store into
the validator gives system-wide deduplication for free.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any, Iterable, Optional, Protocol

from zeropath.knowledge.models import KGEdge, KGNode
from zeropath.knowledge.schema import NodeLabel, RelationshipType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


class KGStore(Protocol):
    """Minimal write/query surface every backend must implement."""

    def upsert_node(self, node: KGNode) -> KGNode: ...
    def upsert_edge(self, edge: KGEdge) -> KGEdge: ...
    def get_node(self, node_id: str) -> Optional[KGNode]: ...
    def find_by_label(self, label: NodeLabel) -> list[KGNode]: ...
    def find_by_property(self, label: NodeLabel, key: str, value: Any) -> list[KGNode]: ...
    def neighbors(
        self, node_id: str, *, rel_type: Optional[RelationshipType] = None,
        direction: str = "out",
    ) -> list[tuple[KGEdge, KGNode]]: ...
    def all_edges(self) -> list[KGEdge]: ...
    def clear(self) -> None: ...

    # Phase 6 DuplicateStore compatibility -----------------------------
    def lookup(self, fingerprint: str) -> Optional[str]: ...
    def record(self, fingerprint: str, validation_id: str) -> None: ...
    def fingerprints(self) -> list[str]: ...


# ---------------------------------------------------------------------------
# In-memory implementation
# ---------------------------------------------------------------------------


class InMemoryKGStore:
    """
    Thread-safe in-process store. JSON-backed via ``snapshot`` / ``restore``.

    Keeps three indexes:
      * ``_nodes`` by ID
      * ``_edges`` by ID
      * ``_by_label`` for fast label scans
    Plus a ``_fingerprints`` dict implementing the Phase 6 DuplicateStore
    contract so the validator and the KG agree on what's a duplicate.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._nodes: dict[str, KGNode] = {}
        self._edges: dict[str, KGEdge] = {}
        self._by_label: dict[NodeLabel, set[str]] = {}
        self._fingerprints: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Node / edge upsert
    # ------------------------------------------------------------------

    def upsert_node(self, node: KGNode) -> KGNode:
        with self._lock:
            existing = self._nodes.get(node.id)
            if existing:
                merged = existing.model_copy(deep=True)
                merged.properties.update(node.properties)
                merged.updated_at = node.updated_at
                self._nodes[node.id] = merged
                return merged
            self._nodes[node.id] = node
            self._by_label.setdefault(node.label, set()).add(node.id)
            return node

    def upsert_edge(self, edge: KGEdge) -> KGEdge:
        with self._lock:
            # Edges are uniquely keyed by (from, to, type) — collapse duplicates.
            for existing in self._edges.values():
                if (
                    existing.from_id == edge.from_id
                    and existing.to_id == edge.to_id
                    and existing.type == edge.type
                ):
                    existing.properties.update(edge.properties)
                    return existing
            self._edges[edge.id] = edge
            return edge

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def get_node(self, node_id: str) -> Optional[KGNode]:
        return self._nodes.get(node_id)

    def find_by_label(self, label: NodeLabel) -> list[KGNode]:
        ids = self._by_label.get(label, set())
        return [self._nodes[i] for i in ids if i in self._nodes]

    def find_by_property(self, label: NodeLabel, key: str, value: Any) -> list[KGNode]:
        out: list[KGNode] = []
        for nid in self._by_label.get(label, set()):
            n = self._nodes.get(nid)
            if n and n.properties.get(key) == value:
                out.append(n)
        return out

    def neighbors(
        self,
        node_id: str,
        *,
        rel_type: Optional[RelationshipType] = None,
        direction: str = "out",
    ) -> list[tuple[KGEdge, KGNode]]:
        results: list[tuple[KGEdge, KGNode]] = []
        for edge in self._edges.values():
            if rel_type is not None and edge.type != rel_type:
                continue
            if direction == "out" and edge.from_id == node_id:
                other = self._nodes.get(edge.to_id)
                if other:
                    results.append((edge, other))
            elif direction == "in" and edge.to_id == node_id:
                other = self._nodes.get(edge.from_id)
                if other:
                    results.append((edge, other))
            elif direction == "both" and (edge.from_id == node_id or edge.to_id == node_id):
                other_id = edge.to_id if edge.from_id == node_id else edge.from_id
                other = self._nodes.get(other_id)
                if other:
                    results.append((edge, other))
        return results

    def all_edges(self) -> list[KGEdge]:
        return list(self._edges.values())

    def clear(self) -> None:
        with self._lock:
            self._nodes.clear()
            self._edges.clear()
            self._by_label.clear()
            self._fingerprints.clear()

    # ------------------------------------------------------------------
    # Phase 6 DuplicateStore compatibility
    # ------------------------------------------------------------------

    def lookup(self, fingerprint: str) -> Optional[str]:
        return self._fingerprints.get(fingerprint)

    def record(self, fingerprint: str, validation_id: str) -> None:
        with self._lock:
            self._fingerprints.setdefault(fingerprint, validation_id)

    def fingerprints(self) -> list[str]:
        return list(self._fingerprints.keys())

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def snapshot(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "nodes": [n.model_dump() for n in self._nodes.values()],
            "edges": [e.model_dump() for e in self._edges.values()],
            "fingerprints": dict(self._fingerprints),
        }
        target.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return target

    def restore(self, path: str | Path) -> None:
        target = Path(path)
        payload = json.loads(target.read_text(encoding="utf-8"))
        self.clear()
        for nd in payload.get("nodes", []):
            self.upsert_node(KGNode.model_validate(nd))
        for ed in payload.get("edges", []):
            self.upsert_edge(KGEdge.model_validate(ed))
        self._fingerprints.update(payload.get("fingerprints", {}))

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)


# ---------------------------------------------------------------------------
# Neo4j implementation
# ---------------------------------------------------------------------------


class Neo4jKGStore:
    """
    Thin Neo4j adapter for the Phase 8 KG. Connects lazily so importing this
    module without a live Neo4j is harmless.

    The constructor mirrors :class:`zeropath.graph_db.Neo4jGraphDB` so the
    same credentials work for both layers (the protocol graph + the KG can
    live in the same DB).
    """

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        database: str = "neo4j",
    ) -> None:
        self.uri = uri
        self.username = username
        self.password = password
        self.database = database
        self._driver = None
        self._fingerprint_cache: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
        if self._driver is not None:
            return
        try:
            from neo4j import GraphDatabase
        except ImportError as exc:  # pragma: no cover — driver listed in deps
            raise RuntimeError(
                "neo4j driver missing — install zeropath with neo4j extras"
            ) from exc
        self._driver = GraphDatabase.driver(self.uri, auth=(self.username, self.password))
        self._apply_schema()

    def disconnect(self) -> None:
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    def __enter__(self) -> "Neo4jKGStore":
        self.connect()
        return self

    def __exit__(self, *_exc) -> None:
        self.disconnect()

    def _apply_schema(self) -> None:
        from zeropath.knowledge.schema import SCHEMA_QUERIES
        with self._driver.session(database=self.database) as session:  # type: ignore[union-attr]
            for q in SCHEMA_QUERIES:
                try:
                    session.run(q).consume()
                except Exception as exc:
                    logger.debug("schema query skipped: %s (%s)", q, exc)

    def _session(self):
        if self._driver is None:
            self.connect()
        return self._driver.session(database=self.database)  # type: ignore[union-attr]

    # ------------------------------------------------------------------
    # Node / edge upsert
    # ------------------------------------------------------------------

    def upsert_node(self, node: KGNode) -> KGNode:
        cypher = (
            f"MERGE (n:{node.label.value} {{id: $id}}) "
            "SET n += $props, n.updated_at = $updated_at "
            "RETURN n"
        )
        with self._session() as session:
            session.run(
                cypher,
                id=node.id,
                props=node.properties,
                updated_at=node.updated_at,
            ).consume()
        return node

    def upsert_edge(self, edge: KGEdge) -> KGEdge:
        cypher = (
            "MATCH (a {id: $from_id}), (b {id: $to_id}) "
            f"MERGE (a)-[r:{edge.type.value}]->(b) "
            "SET r += $props "
            "RETURN r"
        )
        with self._session() as session:
            session.run(
                cypher,
                from_id=edge.from_id,
                to_id=edge.to_id,
                props=edge.properties,
            ).consume()
        return edge

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def get_node(self, node_id: str) -> Optional[KGNode]:
        cypher = "MATCH (n {id: $id}) RETURN labels(n)[0] AS label, properties(n) AS props"
        with self._session() as session:
            row = session.run(cypher, id=node_id).single()
        if not row:
            return None
        return self._row_to_node(row["label"], row["props"])

    def find_by_label(self, label: NodeLabel) -> list[KGNode]:
        with self._session() as session:
            rows = session.run(
                f"MATCH (n:{label.value}) RETURN properties(n) AS props"
            ).data()
        return [self._row_to_node(label.value, r["props"]) for r in rows]

    def find_by_property(self, label: NodeLabel, key: str, value: Any) -> list[KGNode]:
        with self._session() as session:
            rows = session.run(
                f"MATCH (n:{label.value} {{{key}: $value}}) RETURN properties(n) AS props",
                value=value,
            ).data()
        return [self._row_to_node(label.value, r["props"]) for r in rows]

    def neighbors(
        self,
        node_id: str,
        *,
        rel_type: Optional[RelationshipType] = None,
        direction: str = "out",
    ) -> list[tuple[KGEdge, KGNode]]:
        rel_filter = f":{rel_type.value}" if rel_type else ""
        arrow_out = f"-[r{rel_filter}]->" if direction != "in" else f"<-[r{rel_filter}]-"
        cypher = (
            f"MATCH (a {{id: $id}}){arrow_out}(b) "
            "RETURN type(r) AS t, properties(r) AS rp, labels(b)[0] AS label, properties(b) AS props"
        )
        out: list[tuple[KGEdge, KGNode]] = []
        with self._session() as session:
            for row in session.run(cypher, id=node_id).data():
                edge = KGEdge(
                    from_id=node_id,
                    to_id=row["props"].get("id", ""),
                    type=RelationshipType(row["t"]),
                    properties=row["rp"],
                )
                out.append((edge, self._row_to_node(row["label"], row["props"])))
        return out

    def all_edges(self) -> list[KGEdge]:
        with self._session() as session:
            rows = session.run(
                "MATCH (a)-[r]->(b) "
                "RETURN a.id AS f, b.id AS t, type(r) AS rt, properties(r) AS rp"
            ).data()
        return [
            KGEdge(
                from_id=r["f"], to_id=r["t"],
                type=RelationshipType(r["rt"]), properties=r["rp"],
            )
            for r in rows
        ]

    def clear(self) -> None:
        with self._session() as session:
            session.run("MATCH (n) DETACH DELETE n").consume()
        self._fingerprint_cache.clear()

    # ------------------------------------------------------------------
    # Phase 6 DuplicateStore compatibility
    # ------------------------------------------------------------------

    def lookup(self, fingerprint: str) -> Optional[str]:
        if fingerprint in self._fingerprint_cache:
            return self._fingerprint_cache[fingerprint]
        with self._session() as session:
            row = session.run(
                f"MATCH (e:{NodeLabel.VALIDATED_EXPLOIT.value} {{fingerprint: $fp}}) "
                "RETURN e.id AS id LIMIT 1",
                fp=fingerprint,
            ).single()
        if not row:
            return None
        self._fingerprint_cache[fingerprint] = row["id"]
        return row["id"]

    def record(self, fingerprint: str, validation_id: str) -> None:
        # Recording happens implicitly when ingest_exploit() upserts a
        # ValidatedExploit node with the fingerprint property. Keep the
        # cache coherent here.
        self._fingerprint_cache.setdefault(fingerprint, validation_id)

    def fingerprints(self) -> list[str]:
        with self._session() as session:
            rows = session.run(
                f"MATCH (e:{NodeLabel.VALIDATED_EXPLOIT.value}) "
                "WHERE e.fingerprint IS NOT NULL RETURN e.fingerprint AS fp"
            ).data()
        return [r["fp"] for r in rows]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_node(label: str, props: dict[str, Any]) -> KGNode:
        return KGNode(
            id=props.get("id", str(uuid4())),
            label=NodeLabel(label),
            properties={k: v for k, v in props.items() if k not in ("id",)},
            created_at=props.get("created_at") or _utc_now_str(),
            updated_at=props.get("updated_at") or _utc_now_str(),
        )


# Re-imports kept inside the file so this module is self-contained.
from datetime import datetime, timezone
from uuid import uuid4


def _utc_now_str() -> str:
    return datetime.now(timezone.utc).isoformat()
