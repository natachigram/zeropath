"""
Submission strategy — Contest mode.

Decides, for every finding the audit pipeline surfaces:

  1. **Confidence gate** — drop low-confidence findings (don't burn rep)
  2. **Severity floor** — drop findings below the contest's payout floor
  3. **Duplicate-likelihood scoring** — estimate how many other competitors
     will submit the same bug; rank low-dup first so we get unique credit
     before the herd
  4. **Final rank** — composite of severity, confidence, dup_likelihood
"""

from __future__ import annotations

import logging
import math
from typing import Iterable

from zeropath.contest.models import (
    ContestConfig,
    Submission,
    SubmissionDisposition,
    SubmissionFinding,
)
from zeropath.knowledge.knowledge import KnowledgeGraphOrchestrator

logger = logging.getLogger(__name__)


# Severity → integer for floor checks.
_SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
}


def _sev_int(sev: str) -> int:
    return _SEVERITY_ORDER.get((sev or "medium").lower(), 3)


# ---------------------------------------------------------------------------
# Duplicate-likelihood model
# ---------------------------------------------------------------------------


# Per-attack-class baseline duplicate likelihood. Calibrated against
# observed Code4rena / Cantina contest data: well-known classes get
# submitted many times by many wardens.
_BASELINE_DUP: dict[str, float] = {
    "reentrancy": 0.85,
    "access_control": 0.80,
    "oracle_manipulation": 0.75,
    "flash_loan": 0.70,
    "integer_math": 0.65,
    "governance": 0.55,
    "composability": 0.45,
    "price_manipulation": 0.65,
    "spec_violation": 0.40,    # bespoke claims tend to be lower-dup
    "other": 0.50,
}


def _kg_dup_boost(
    attack_class: str,
    knowledge: KnowledgeGraphOrchestrator | None,
) -> float:
    """
    If we've ingested past contest reports into Phase 8, classes with
    many historical findings of that type get a small dup boost — they're
    well-known, so other wardens will find them too.
    """
    if knowledge is None:
        return 0.0
    try:
        dist = {}
        from zeropath.llm.audit_corpus import AuditCorpus
        dist = AuditCorpus(knowledge).attack_class_distribution()
    except Exception:
        dist = {}
    total = sum(dist.values()) or 1
    share = dist.get(attack_class, 0) / total
    return min(0.20, share * 0.5)


def estimate_duplicate_likelihood(
    finding: SubmissionFinding,
    *,
    knowledge: KnowledgeGraphOrchestrator | None = None,
) -> float:
    """
    Heuristic duplicate-likelihood score in [0,1].

    Components:
      * Per-attack-class baseline
      * KG-driven boost when the class is well-attested
      * Novelty discount when the LLM explicitly flagged the bug as one
        humans might miss
      * Confidence-driven mild discount (we're sure → likely subtle → less dup)
    """
    base = _BASELINE_DUP.get((finding.attack_class or "other").lower(), 0.5)
    base += _kg_dup_boost(finding.attack_class, knowledge)

    # Spec-violation findings tend to be unique to the protocol.
    if finding.spec_claim_source:
        base -= 0.20

    # LLM novelty notes drop dup further.
    novelty = (finding.novelty_assessment or "").lower()
    if any(kw in novelty for kw in ("subtle", "missed", "non-obvious", "edge", "rare")):
        base -= 0.10

    # Very high confidence on a subtle finding → likely uniquely found.
    if finding.confidence >= 0.85:
        base -= 0.05

    return max(0.05, min(0.95, round(base, 3)))


# ---------------------------------------------------------------------------
# Strategy
# ---------------------------------------------------------------------------


class SubmissionStrategy:
    """
    Gate + rank findings into a submission queue.

    Parameters
    ----------
    config : ContestConfig
        The active contest configuration.
    knowledge : KnowledgeGraphOrchestrator | None
        Phase 8 KG used for dup-likelihood + novelty signals.
    """

    def __init__(
        self,
        config: ContestConfig,
        *,
        knowledge: KnowledgeGraphOrchestrator | None = None,
    ) -> None:
        self.config = config
        self.knowledge = knowledge
        self._severity_floor_int = _sev_int(config.submit_severity_floor)

    # ------------------------------------------------------------------

    def assess(self, findings: Iterable[SubmissionFinding]) -> list[Submission]:
        """
        Build :class:`Submission` rows from raw findings, set dispositions,
        and assign ranks.

        Returns the list sorted by composite rank ascending (rank 1 = top).
        """
        prepared: list[Submission] = []
        for f in findings:
            f.duplicate_likelihood = estimate_duplicate_likelihood(
                f, knowledge=self.knowledge,
            )
            disposition = self._disposition_for(f)
            prepared.append(Submission(
                finding=f,
                disposition=disposition,
                platform=self.config.platform,
            ))
        # Rank only the actionable ones; others get rank=0.
        actionable = [s for s in prepared if s.is_actionable]
        actionable.sort(key=lambda s: self._rank_key(s.finding))
        for i, s in enumerate(actionable, start=1):
            s.rank = i
        return prepared

    # ------------------------------------------------------------------

    def _disposition_for(self, f: SubmissionFinding) -> SubmissionDisposition:
        if f.contrarian_objections and any(
            "discard" in obj.lower() or "invalid" in obj.lower()
            for obj in f.contrarian_objections
        ):
            return SubmissionDisposition.DISCARD
        if _sev_int(f.severity) < self._severity_floor_int:
            return SubmissionDisposition.HOLD
        if f.confidence < self.config.submit_confidence_threshold:
            return SubmissionDisposition.HOLD
        # SUBMIT_NOW when low dup OR very high severity; else SUBMIT_LATER.
        if f.duplicate_likelihood <= 0.40 or _sev_int(f.severity) >= _sev_int("critical"):
            return SubmissionDisposition.SUBMIT_NOW
        return SubmissionDisposition.SUBMIT_LATER

    @staticmethod
    def _rank_key(f: SubmissionFinding) -> tuple[float, float, float, float]:
        """
        Lower key = higher rank.

        Order:
          1. Negative severity (critical first)
          2. Duplicate likelihood (unique first)
          3. Negative confidence (most confident first)
          4. Negative profit signal (if any — fallback to title length)
        """
        return (
            -_sev_int(f.severity),
            f.duplicate_likelihood,
            -f.confidence,
            -float(len(f.attack_path)),     # richer attack paths = better
        )
