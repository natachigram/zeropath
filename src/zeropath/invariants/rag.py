"""
RAG (Retrieval-Augmented Generation) index over the exploit database.

This is a lightweight, pure-Python implementation — no vector store or
external dependencies.  It uses:

  1. Invariant-type exact matching   (primary signal)
  2. Tag-based keyword overlap        (secondary signal)
  3. Loss-magnitude weighting        (tertiary signal)

For Phase 2, this is sufficient: every invariant type maps cleanly to a
subset of the exploit DB, and tag overlap disambiguates between them.

The RAG is consulted by each invariant detector to:
  - Attach HistoricalPrecedent records to Invariant objects
  - Boost confidence scores when strong precedent exists
  - Provide evidence text summarising the historical context

Phase 8 replaces this with a proper GraphRAG + Neo4j implementation.
Until then this gives every detector access to grounded, real-world signal.
"""

from __future__ import annotations

from zeropath.invariants.exploit_db import EXPLOIT_DB
from zeropath.invariants.models import HistoricalPrecedent, InvariantType


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimum number of tag overlaps to consider a precedent "highly relevant"
_HIGH_RELEVANCE_TAG_OVERLAP = 2

# How much each precedent boosts confidence (diminishing: first hit counts most)
_CONFIDENCE_PER_PRECEDENT = 0.08
_MAX_CONFIDENCE_BOOST = 0.35


# ---------------------------------------------------------------------------
# RAG index
# ---------------------------------------------------------------------------


class ExploitRAG:
    """
    Retrieval index over the static exploit database.

    Usage::

        rag = ExploitRAG()
        precedents = rag.query(InvariantType.ORACLE_MANIPULATION, tags={"flash_loan"})
        boost = rag.confidence_boost(precedents)
    """

    def __init__(self) -> None:
        # Pre-group by invariant type for O(1) primary lookup
        self._by_type: dict[InvariantType, list[HistoricalPrecedent]] = {}
        for entry in EXPLOIT_DB:
            self._by_type.setdefault(entry.invariant_type, []).append(entry)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def query(
        self,
        invariant_type: InvariantType,
        tags: set[str] | None = None,
        max_results: int = 5,
    ) -> list[HistoricalPrecedent]:
        """
        Return the most relevant historical precedents for an invariant type.

        Args:
            invariant_type: The invariant class to look up.
            tags: Optional set of context tags (from pattern detection) to
                  refine ranking.  E.g. {"flash_loan", "oracle"}.
            max_results: Maximum number of precedents to return.

        Returns:
            Ranked list of HistoricalPrecedent, highest relevance first.
        """
        candidates = list(self._by_type.get(invariant_type, []))
        if not candidates:
            return []

        if tags:
            candidates = _rank_by_tags(candidates, tags)
        else:
            # Default: sort by loss magnitude (most costly incidents first)
            candidates = sorted(candidates, key=lambda e: e.loss_usd, reverse=True)

        return candidates[:max_results]

    def confidence_boost(
        self,
        precedents: list[HistoricalPrecedent],
    ) -> float:
        """
        Calculate a confidence boost based on the number and quality of
        historical precedents retrieved.

        Returns a value in [0.0, MAX_CONFIDENCE_BOOST].
        """
        if not precedents:
            return 0.0
        boost = min(
            len(precedents) * _CONFIDENCE_PER_PRECEDENT,
            _MAX_CONFIDENCE_BOOST,
        )
        # Extra boost if any precedent involved very large losses (> $10M)
        if any(p.loss_usd >= 10_000_000 for p in precedents):
            boost = min(boost + 0.05, _MAX_CONFIDENCE_BOOST)
        return round(boost, 3)

    def evidence_summary(
        self,
        precedents: list[HistoricalPrecedent],
    ) -> str:
        """
        Build a human-readable evidence string from retrieved precedents.

        Example output:
          "Historically violated in: Euler Finance ($197M, 2023-03-13),
           Beanstalk ($182M, 2022-04-17)"
        """
        if not precedents:
            return ""
        items = [
            f"{p.protocol} (${p.loss_usd:,}, {p.date})"
            for p in precedents[:3]
        ]
        return "Historically violated in: " + ", ".join(items)

    def all_types(self) -> list[InvariantType]:
        """Return invariant types that have at least one precedent."""
        return list(self._by_type.keys())


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _rank_by_tags(
    candidates: list[HistoricalPrecedent],
    query_tags: set[str],
) -> list[HistoricalPrecedent]:
    """
    Rank candidates by tag overlap with query_tags, breaking ties by loss_usd.
    """
    def score(entry: HistoricalPrecedent) -> tuple[int, int]:
        overlap = len(set(entry.tags) & query_tags)
        return (overlap, entry.loss_usd)

    return sorted(candidates, key=score, reverse=True)


# ---------------------------------------------------------------------------
# Module-level singleton (avoids repeated construction)
# ---------------------------------------------------------------------------

_RAG_INSTANCE: ExploitRAG | None = None


def get_rag() -> ExploitRAG:
    """Return the module-level singleton RAG instance."""
    global _RAG_INSTANCE
    if _RAG_INSTANCE is None:
        _RAG_INSTANCE = ExploitRAG()
    return _RAG_INSTANCE
