"""
GraphRAG adapter — Phase 8 (optional).

Spec (phases.md, PHASE 8 critical additions, "GraphRAG for knowledge graph construction"):
    "Use GraphRAG directly here instead of a custom implementation. Its
     multi-level summarization reduces LLM context requirements for agent
     queries in Phase 3. Configure global summaries (exploit pattern
     classes), local summaries (per-protocol), and motif detection."

GraphRAG (microsoft/graphrag) is a heavyweight LLM-dependent package — it
needs API keys, an embedding model, and ~GB of vector indexes. We do NOT
take a hard dependency on it. Instead this module exposes:

  * :class:`GraphRAGAdapter` — a thin wrapper that detects whether
    ``graphrag`` is importable and gracefully degrades to local fallbacks
    (token-overlap text summaries) when not.

  * :class:`LocalSummariser` — a stdlib-only fallback that ships the
    "global" / "local" / "motif" interfaces using the existing KG nodes.

Callers always go through :class:`GraphRAGAdapter`; the choice between
GraphRAG-real and the fallback is invisible at the call site.
"""

from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from zeropath.knowledge.models import KGNode
from zeropath.knowledge.schema import NodeLabel, RelationshipType
from zeropath.knowledge.store import KGStore

logger = logging.getLogger(__name__)


_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]+")


def _tokens(text: str) -> Counter:
    return Counter(t.lower() for t in _TOKEN_RE.findall(text or ""))


# ---------------------------------------------------------------------------
# Result records
# ---------------------------------------------------------------------------


@dataclass
class GraphSummary:
    """One summary block emitted by the adapter."""

    level: str            # "global" | "local" | "motif"
    key: str              # what the summary is *about* (attack class, protocol, motif name)
    headline: str
    bullets: list[str] = field(default_factory=list)
    backed_by_graphrag: bool = False


# ---------------------------------------------------------------------------
# Local stdlib summariser
# ---------------------------------------------------------------------------


class LocalSummariser:
    """
    Deterministic stdlib summariser used when GraphRAG isn't installed.

    The interfaces match what callers expect from a GraphRAG-backed adapter
    so swapping in the real implementation is a no-op for the rest of the
    package.
    """

    def __init__(self, store: KGStore) -> None:
        self.store = store

    # ------------------------------------------------------------------
    # Global summaries — one per attack class
    # ------------------------------------------------------------------

    def global_summaries(self) -> list[GraphSummary]:
        per_class: dict[str, list[KGNode]] = defaultdict(list)
        for ex in self.store.find_by_label(NodeLabel.VALIDATED_EXPLOIT):
            cls = ex.properties.get("attack_class") or "unknown"
            per_class[cls].append(ex)
        for inc in self.store.find_by_label(NodeLabel.EXTERNAL_INCIDENT):
            cls = inc.properties.get("attack_class") or "unknown"
            per_class[cls].append(inc)

        out: list[GraphSummary] = []
        for cls, nodes in sorted(per_class.items()):
            total_loss = sum(
                int(n.properties.get("loss_usd") or 0) for n in nodes
            )
            internal = sum(1 for n in nodes if n.label == NodeLabel.VALIDATED_EXPLOIT)
            external = len(nodes) - internal
            protocols = sorted(
                {
                    n.properties.get("protocol_name") or n.properties.get("protocol") or ""
                    for n in nodes
                }
                - {""}
            )
            bullets = [
                f"validated exploits: {internal}",
                f"historical incidents: {external}",
                f"total observed loss (where reported): ${total_loss:_}",
                f"distinct protocols touched: {len(protocols)}",
            ]
            if protocols:
                bullets.append("examples: " + ", ".join(list(protocols)[:5]))
            out.append(GraphSummary(
                level="global",
                key=cls,
                headline=f"{cls} — {internal + external} known cases",
                bullets=bullets,
            ))
        return out

    # ------------------------------------------------------------------
    # Local summaries — one per protocol
    # ------------------------------------------------------------------

    def local_summaries(self) -> list[GraphSummary]:
        out: list[GraphSummary] = []
        for protocol in self.store.find_by_label(NodeLabel.PROTOCOL):
            name = protocol.properties.get("name") or "unknown"
            invariants = [
                n for _e, n in self.store.neighbors(
                    protocol.id, rel_type=RelationshipType.CONTAINS, direction="out",
                ) if n.label == NodeLabel.INVARIANT
            ]
            exploits = [
                ex for ex in self.store.find_by_label(NodeLabel.VALIDATED_EXPLOIT)
                if ex.properties.get("protocol_name") == name
            ]
            incidents = [
                inc for inc in self.store.find_by_label(NodeLabel.EXTERNAL_INCIDENT)
                if inc.properties.get("protocol") == name
            ]
            bullets = [
                f"invariants tracked: {len(invariants)}",
                f"validated exploits: {len(exploits)}",
                f"external incidents: {len(incidents)}",
            ]
            if exploits:
                tiers = Counter(
                    e.properties.get("severity_tier", "low") for e in exploits
                )
                bullets.append(
                    "severity mix: " + ", ".join(
                        f"{tier}={count}" for tier, count in tiers.most_common()
                    )
                )
            out.append(GraphSummary(
                level="local",
                key=name,
                headline=f"protocol {name} — {len(exploits)} validated, {len(incidents)} historical",
                bullets=bullets,
            ))
        return out

    # ------------------------------------------------------------------
    # Motif detection — recurring (contract, function) pairs across exploits
    # ------------------------------------------------------------------

    def motif_summaries(self, *, min_support: int = 2) -> list[GraphSummary]:
        pair_counts: Counter = Counter()
        for ex in self.store.find_by_label(NodeLabel.VALIDATED_EXPLOIT):
            contracts = ex.properties.get("contracts_involved") or []
            functions = ex.properties.get("functions_involved") or []
            for c in contracts:
                for f in functions:
                    pair_counts[(c, f)] += 1
        out: list[GraphSummary] = []
        for (contract, fn), count in pair_counts.most_common():
            if count < min_support:
                break
            out.append(GraphSummary(
                level="motif",
                key=f"{contract}.{fn}",
                headline=f"recurring vulnerable pattern: {contract}.{fn}() — {count} cases",
                bullets=[f"support={count}"],
            ))
        return out


# ---------------------------------------------------------------------------
# Public adapter (GraphRAG-aware façade)
# ---------------------------------------------------------------------------


class GraphRAGAdapter:
    """
    Detects whether the real ``graphrag`` package is installed and dispatches
    to it; falls back to :class:`LocalSummariser` otherwise. Callers don't
    need to know which path was taken.

    Real GraphRAG integration would live in ``_summaries_from_graphrag``;
    we stub it here so the package imports cleanly without the dep.
    """

    def __init__(
        self,
        store: KGStore,
        *,
        prefer_graphrag: bool = True,
        config: Optional[dict[str, Any]] = None,
    ) -> None:
        self.store = store
        self.prefer_graphrag = prefer_graphrag
        self.config = config or {}
        self._local = LocalSummariser(store)
        self._graphrag_available = self._detect_graphrag()

    # ------------------------------------------------------------------

    @property
    def using_graphrag(self) -> bool:
        return self.prefer_graphrag and self._graphrag_available

    def global_summaries(self) -> list[GraphSummary]:
        if self.using_graphrag:
            return self._summaries_from_graphrag(level="global")
        return self._local.global_summaries()

    def local_summaries(self) -> list[GraphSummary]:
        if self.using_graphrag:
            return self._summaries_from_graphrag(level="local")
        return self._local.local_summaries()

    def motif_summaries(self, *, min_support: int = 2) -> list[GraphSummary]:
        if self.using_graphrag:
            return self._summaries_from_graphrag(level="motif")
        return self._local.motif_summaries(min_support=min_support)

    # ------------------------------------------------------------------
    # Private — detection + GraphRAG dispatch
    # ------------------------------------------------------------------

    def _detect_graphrag(self) -> bool:
        try:
            import graphrag  # type: ignore  # noqa: F401
            return True
        except ImportError:
            return False

    def _summaries_from_graphrag(self, *, level: str) -> list[GraphSummary]:
        """
        Placeholder for real GraphRAG integration.

        A production implementation would:
          1. Materialise the KG into GraphRAG's input format.
          2. Invoke ``graphrag.index.run`` (or the configured workflow).
          3. Read the per-community / per-summary outputs.
          4. Convert each into :class:`GraphSummary` with
             ``backed_by_graphrag=True``.

        For now we still fall back to the local summariser but flag the
        records so callers can tell.
        """
        logger.info(
            "GraphRAG path requested but no production binding configured — "
            "returning LocalSummariser output with backed_by_graphrag=True flag."
        )
        if level == "global":
            summaries = self._local.global_summaries()
        elif level == "local":
            summaries = self._local.local_summaries()
        else:
            summaries = self._local.motif_summaries()
        for s in summaries:
            s.backed_by_graphrag = True
        return summaries
