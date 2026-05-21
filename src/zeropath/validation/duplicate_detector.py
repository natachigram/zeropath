"""
Duplicate detector — Phase 6.

Spec (phases.md, PHASE 6 critical additions, "Duplicate detection"):
    "As the system matures, it will find the same vulnerability multiple
     ways. Deduplicate validated exploits against Phase 8 knowledge graph
     before surfacing. Do not report the same root cause twice."

Phase 8 (GraphRAG / Neo4j) is not built yet, so this module:

  1. Computes a stable **fingerprint** of the root cause from the attack
     hypothesis. Same root cause → same fingerprint.
  2. Looks the fingerprint up in a pluggable backend:
       * :class:`InMemoryDuplicateStore` — default, used for offline runs
         and tests; persists nothing.
       * Any object implementing :class:`DuplicateStore` (Phase 8 will plug
         a Neo4j-backed store here).

Fingerprint composition:

  attack_class | sorted(contracts) | sorted(functions) | sorted(state_vars)

That tuple is hashed with SHA-256 and truncated. Two hypotheses that exploit
the same code path through different agents converge to the same fingerprint;
two hypotheses that target different vulnerable functions stay distinct.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from typing import Iterable, Optional, Protocol

from zeropath.adversarial.models import AttackHypothesis

logger = logging.getLogger(__name__)


def compute_fingerprint(hypothesis: AttackHypothesis) -> str:
    """
    Stable 32-hex fingerprint of an exploit's root cause.

    Inputs: attack_class + sorted(contracts_involved) + sorted(functions_involved)
            + sorted(state_vars_involved).

    Two hypotheses with identical input sets produce the same fingerprint
    irrespective of which agent generated them, which narrative they used,
    or which preconditions they listed.
    """
    parts = [
        hypothesis.attack_class.value,
        "|".join(sorted(c.lower() for c in (hypothesis.contracts_involved or []))),
        "|".join(sorted(f.lower() for f in (hypothesis.functions_involved or []))),
        "|".join(sorted(v.lower() for v in (hypothesis.state_vars_involved or []))),
    ]
    payload = "||".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Store protocol
# ---------------------------------------------------------------------------


class DuplicateStore(Protocol):
    """
    Minimal interface the detector needs. Phase 8 will provide a Neo4j /
    GraphRAG implementation; until then, ``InMemoryDuplicateStore`` is the
    default.
    """

    def lookup(self, fingerprint: str) -> Optional[str]:
        """Return the validation_id of a prior finding, or None."""

    def record(self, fingerprint: str, validation_id: str) -> None:
        """Persist a (fingerprint → validation_id) mapping."""


class InMemoryDuplicateStore:
    """Thread-safe in-process store. Resets every process restart."""

    def __init__(self, seed: Optional[dict[str, str]] = None) -> None:
        self._table: dict[str, str] = dict(seed or {})
        self._lock = threading.Lock()

    def lookup(self, fingerprint: str) -> Optional[str]:
        with self._lock:
            return self._table.get(fingerprint)

    def record(self, fingerprint: str, validation_id: str) -> None:
        with self._lock:
            self._table.setdefault(fingerprint, validation_id)

    def __len__(self) -> int:
        return len(self._table)

    def fingerprints(self) -> list[str]:
        return list(self._table.keys())


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class DuplicateDetector:
    """
    Lookup + record interface for the validator orchestrator.

    Parameters
    ----------
    store : DuplicateStore | None
        Backing store. Defaults to a fresh :class:`InMemoryDuplicateStore`.
    record_on_lookup : bool
        When True (default), a *miss* records the new fingerprint
        immediately so subsequent hypotheses in the same batch dedupe
        against it. Set to False if you want to record only after a full
        validation pass.
    """

    def __init__(
        self,
        store: Optional[DuplicateStore] = None,
        *,
        record_on_lookup: bool = True,
    ) -> None:
        self.store = store or InMemoryDuplicateStore()
        self.record_on_lookup = record_on_lookup

    # ------------------------------------------------------------------

    def check(
        self,
        hypothesis: AttackHypothesis,
        validation_id: str,
    ) -> tuple[str, Optional[str]]:
        """
        Return (fingerprint, duplicate_of).

        * ``duplicate_of`` = ID of an earlier validation when seen before.
        * ``duplicate_of`` = None on first encounter; if
          ``record_on_lookup`` is True, the new fingerprint is recorded
          immediately so this same batch doesn't double-report.
        """
        fp = compute_fingerprint(hypothesis)
        prior = self.store.lookup(fp)
        if prior is None and self.record_on_lookup:
            self.store.record(fp, validation_id)
        return fp, prior

    def record(self, fingerprint: str, validation_id: str) -> None:
        self.store.record(fingerprint, validation_id)

    # ------------------------------------------------------------------
    # Batch dedup convenience
    # ------------------------------------------------------------------

    def deduplicate(
        self, hypotheses: Iterable[AttackHypothesis]
    ) -> list[tuple[AttackHypothesis, str, Optional[str]]]:
        """
        Run check() over an iterable, returning (hypothesis, fingerprint, dup_of).

        Useful for an offline batch where the orchestrator hasn't been
        wired in yet.
        """
        out: list[tuple[AttackHypothesis, str, Optional[str]]] = []
        for h in hypotheses:
            fp, dup = self.check(h, validation_id=h.id)
            out.append((h, fp, dup))
        return out
