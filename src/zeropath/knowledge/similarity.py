"""
Similarity engine — Phase 8.

Spec (phases.md, PHASE 8 LLM prompt):
    "Implement similarity queries:
       - find protocols with similar graph structures to known-hacked protocols
       - find invariants matching the class of a historical exploit
       - find exploit sequences similar to previously validated ones (dedup)"

The engine ranks candidates with two cheap, deterministic measures (no
embedding service, no torch):

  * **Jaccard set similarity** over token bags — protocol functions,
    invariant evidence words, attack-class tags.
  * **Cosine similarity over feature vectors** for sequences whose
    ``protocols_touched`` / ``attack_class`` produce a stable feature set.

The output is a list of :class:`SimilarityHit` rows sorted by score; the
top-K cutoff is the caller's responsibility.
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from typing import Iterable, Optional

from zeropath.knowledge.models import KGNode, SimilarityHit
from zeropath.knowledge.schema import NodeLabel, RelationshipType
from zeropath.knowledge.store import KGStore

logger = logging.getLogger(__name__)


_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN_RE.findall(text or "")}


def jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    """Jaccard similarity over two token sets. 0 when both are empty."""
    set_a, set_b = set(a), set(b)
    if not set_a and not set_b:
        return 0.0
    inter = len(set_a & set_b)
    union = len(set_a | set_b)
    return inter / union if union else 0.0


def cosine(vec_a: Counter, vec_b: Counter) -> float:
    if not vec_a or not vec_b:
        return 0.0
    common = set(vec_a) & set(vec_b)
    dot = sum(vec_a[k] * vec_b[k] for k in common)
    norm_a = math.sqrt(sum(v * v for v in vec_a.values()))
    norm_b = math.sqrt(sum(v * v for v in vec_b.values()))
    if not norm_a or not norm_b:
        return 0.0
    return dot / (norm_a * norm_b)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class SimilarityEngine:
    """
    Cross-record similarity queries over the KG.

    Parameters
    ----------
    store : KGStore
        Backend the engine reads from.
    top_k : int
        Default top-K returned by every query. Callers can override.
    """

    def __init__(self, store: KGStore, *, top_k: int = 5) -> None:
        self.store = store
        self.top_k = top_k

    # ------------------------------------------------------------------
    # Protocol-vs-protocol (graph structure similarity)
    # ------------------------------------------------------------------

    def find_similar_protocols(
        self,
        protocol_name: str,
        *,
        top_k: Optional[int] = None,
    ) -> list[SimilarityHit]:
        """
        Rank protocols by Jaccard similarity over the set of function names
        their KG nodes share.
        """
        top_k = top_k or self.top_k
        targets = {p.properties.get("name"): p for p in self.store.find_by_label(NodeLabel.PROTOCOL)}
        if protocol_name not in targets:
            return []
        query_fns = self._functions_of(protocol_name)
        out: list[SimilarityHit] = []
        for name, node in targets.items():
            if name == protocol_name:
                continue
            candidate_fns = self._functions_of(name)
            score = jaccard(query_fns, candidate_fns)
            if score <= 0:
                continue
            out.append(SimilarityHit(
                target_id=node.id,
                target_label=NodeLabel.PROTOCOL,
                target_name=name,
                score=round(score, 4),
                reason=f"shared functions: {len(query_fns & candidate_fns)}",
                properties=node.properties,
            ))
        out.sort(key=lambda h: h.score, reverse=True)
        return out[:top_k]

    # ------------------------------------------------------------------
    # Invariant-vs-incident (historical grounding)
    # ------------------------------------------------------------------

    def find_invariants_matching_incident(
        self,
        incident_id: str,
        *,
        top_k: Optional[int] = None,
    ) -> list[SimilarityHit]:
        top_k = top_k or self.top_k
        incident = self.store.get_node(incident_id)
        if not incident:
            return []
        target_class = incident.properties.get("attack_class", "")
        target_tokens = _tokens(incident.properties.get("root_cause", "")) | _tokens(
            " ".join(incident.properties.get("tags", []) or [])
        )
        out: list[SimilarityHit] = []
        for inv in self.store.find_by_label(NodeLabel.INVARIANT):
            class_match = inv.properties.get("type") == target_class
            inv_tokens = _tokens(inv.properties.get("description", ""))
            text_sim = jaccard(target_tokens, inv_tokens)
            score = (0.7 if class_match else 0.0) + 0.3 * text_sim
            if score <= 0:
                continue
            out.append(SimilarityHit(
                target_id=inv.id,
                target_label=NodeLabel.INVARIANT,
                target_name=inv.properties.get("description", "")[:80],
                score=round(score, 4),
                reason=(
                    "attack-class match" if class_match else "description token overlap"
                ),
                properties=inv.properties,
            ))
        out.sort(key=lambda h: h.score, reverse=True)
        return out[:top_k]

    # ------------------------------------------------------------------
    # Exploit-vs-exploit (dedup / cross-protocol generalisation)
    # ------------------------------------------------------------------

    def find_similar_exploits(
        self,
        exploit_id: str,
        *,
        top_k: Optional[int] = None,
    ) -> list[SimilarityHit]:
        top_k = top_k or self.top_k
        query = self.store.get_node(exploit_id)
        if not query:
            return []
        q_vec = self._exploit_feature_vector(query)
        q_class = query.properties.get("attack_class")
        out: list[SimilarityHit] = []
        for cand in self.store.find_by_label(NodeLabel.VALIDATED_EXPLOIT):
            if cand.id == exploit_id:
                continue
            c_vec = self._exploit_feature_vector(cand)
            score = cosine(q_vec, c_vec)
            # Bias up when attack_class matches (a same-class hit beats a
            # different-class lexical coincidence).
            if cand.properties.get("attack_class") == q_class:
                score = min(1.0, score + 0.10)
            if score <= 0:
                continue
            out.append(SimilarityHit(
                target_id=cand.id,
                target_label=NodeLabel.VALIDATED_EXPLOIT,
                target_name=cand.properties.get("protocol_name", "")[:80],
                score=round(score, 4),
                reason="feature-vector cosine",
                properties=cand.properties,
            ))
        out.sort(key=lambda h: h.score, reverse=True)
        return out[:top_k]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _functions_of(self, protocol_name: str) -> set[str]:
        """All function names contained in a given Protocol node."""
        protocols = self.store.find_by_property(
            NodeLabel.PROTOCOL, "name", protocol_name
        )
        if not protocols:
            return set()
        protocol = protocols[0]
        names: set[str] = set()
        for _edge, neighbor in self.store.neighbors(
            protocol.id, rel_type=RelationshipType.CONTAINS, direction="out"
        ):
            if neighbor.label == NodeLabel.FUNCTION:
                fn_name = neighbor.properties.get("name")
                if fn_name:
                    names.add(fn_name)
        return names

    @staticmethod
    def _exploit_feature_vector(node: KGNode) -> Counter:
        """
        Build a Counter feature vector for one exploit node.

        Features:
          * attack_class             (weight 3)
          * contracts_involved       (weight 2 each)
          * functions_involved       (weight 2 each)
          * state_vars_involved      (weight 1 each)
          * severity_tier            (weight 1)
        """
        feats: Counter = Counter()
        props = node.properties
        if cls := props.get("attack_class"):
            feats[f"class::{cls}"] += 3
        for c in props.get("contracts_involved") or []:
            feats[f"contract::{c.lower()}"] += 2
        for f in props.get("functions_involved") or []:
            feats[f"fn::{f.lower()}"] += 2
        for v in props.get("state_vars_involved") or []:
            feats[f"var::{v.lower()}"] += 1
        if tier := props.get("severity_tier"):
            feats[f"tier::{tier}"] += 1
        return feats
