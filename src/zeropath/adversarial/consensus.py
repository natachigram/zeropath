"""
ConsensusAggregator — Phase 3 deduplication and ranking.

After debate, this module:
  1. Removes REJECTED hypotheses (configurable)
  2. Deduplicates: same (invariant_id, attack_class) from different agents → keep best
  3. Ranks by composite score: confidence * 0.5 + specificity * 0.3 + consensus * 0.2
  4. Returns final sorted list for the SwarmReport
"""

from __future__ import annotations

import logging

from zeropath.adversarial.models import AttackHypothesis, AttackClass, HypothesisStatus

logger = logging.getLogger(__name__)

# Ranking weights
_W_CONFIDENCE = 0.50
_W_SPECIFICITY = 0.30
_W_CONSENSUS = 0.20

# Minimum composite score to keep a hypothesis
_MIN_COMPOSITE = 0.20


def _composite_score(h: AttackHypothesis) -> float:
    return (
        h.confidence * _W_CONFIDENCE
        + h.specificity_score * _W_SPECIFICITY
        + h.agent_consensus_score * _W_CONSENSUS
    )


class ConsensusAggregator:
    """
    Post-debate deduplication and ranking.

    Parameters
    ----------
    keep_rejected : bool
        If True, REJECTED hypotheses are included (marked) rather than dropped.
        Useful for audit trails.  Default: False.
    max_per_invariant : int
        Maximum hypotheses to keep per (invariant_id, attack_class) pair.
        Default: 3.
    """

    def __init__(
        self,
        keep_rejected: bool = False,
        max_per_invariant: int = 3,
    ) -> None:
        self.keep_rejected = keep_rejected
        self.max_per_invariant = max_per_invariant

    def aggregate(
        self, hypotheses: list[AttackHypothesis]
    ) -> list[AttackHypothesis]:
        """
        Full aggregation pipeline:
        1. Filter rejected (unless keep_rejected=True)
        2. Deduplicate by (invariant_id, attack_class) — keep top max_per_invariant
        3. Rank survivors by composite score
        4. Drop composites below MIN_COMPOSITE
        """
        # Step 1: filter
        candidates = [
            h for h in hypotheses
            if self.keep_rejected or h.status != HypothesisStatus.REJECTED
        ]

        # Step 2: deduplicate
        candidates = self._deduplicate(candidates)

        # Step 3: score
        for h in candidates:
            h.confidence = max(0.0, min(1.0, h.confidence))  # clamp

        # Step 4: filter below threshold
        candidates = [h for h in candidates if _composite_score(h) >= _MIN_COMPOSITE]

        # Step 5: sort by composite score descending
        candidates.sort(key=_composite_score, reverse=True)

        logger.debug(
            "ConsensusAggregator: %d hypotheses after dedup+rank", len(candidates)
        )
        return candidates

    def _deduplicate(
        self, hypotheses: list[AttackHypothesis]
    ) -> list[AttackHypothesis]:
        """
        For each (invariant_id, attack_class) bucket, keep up to max_per_invariant
        highest-scoring hypotheses.  Different titles within the same bucket
        are kept if they offer materially different attack paths.
        """
        buckets: dict[tuple[str, AttackClass], list[AttackHypothesis]] = {}
        for h in hypotheses:
            key = (h.invariant_id, h.attack_class)
            buckets.setdefault(key, []).append(h)

        result: list[AttackHypothesis] = []
        for (inv_id, cls), group in buckets.items():
            # Sort group by composite score, keep top N
            group.sort(key=_composite_score, reverse=True)
            kept = self._pick_diverse(group, self.max_per_invariant)
            result.extend(kept)

        return result

    @staticmethod
    def _pick_diverse(
        group: list[AttackHypothesis], max_n: int
    ) -> list[AttackHypothesis]:
        """
        From a scored group, pick up to max_n hypotheses that are sufficiently
        diverse (different titles / different attack steps).
        """
        if len(group) <= max_n:
            return group

        picked: list[AttackHypothesis] = []
        seen_titles: set[str] = set()

        for h in group:
            # Normalise title to first 40 chars for similarity check
            norm_title = h.title[:40].lower()
            if norm_title not in seen_titles:
                picked.append(h)
                seen_titles.add(norm_title)
            if len(picked) >= max_n:
                break

        # If diversity picking didn't fill max_n, top up with highest-scored
        if len(picked) < max_n:
            for h in group:
                if h not in picked:
                    picked.append(h)
                if len(picked) >= max_n:
                    break

        return picked
