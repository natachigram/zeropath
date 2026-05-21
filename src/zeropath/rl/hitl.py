"""
HumanInTheLoop — Phase 7.

Spec (phases.md, PHASE 7 critical additions, "Human-in-the-loop"):
    "Provide an interface for a security researcher to:
       - mark a discovered sequence as 'promising' (positive reward injection)
       - mark a sequence as 'not viable' (negative reward injection)
       - suggest a new mutation to try
     This allows domain expertise to guide exploration without replacing it."

The interface is a thread-safe in-memory queue keyed by the artefacts a
human can reference: sequence_id, hypothesis_id, or root-cause
fingerprint (from Phase 6 ``compute_fingerprint``).

When the orchestrator pulls signals before each episode, it filters by:
  * direct sequence/hypothesis match on the seed sequence, OR
  * fingerprint match against any sequence the agent will see.

Signals can be marked "one-shot" (consumed on first application) or
"persistent" (stay in the inbox until the researcher clears them).
"""

from __future__ import annotations

import logging
import threading
from typing import Iterable, Optional

from zeropath.rl.models import HITLSignal, HITLSignalType

logger = logging.getLogger(__name__)


class HumanInTheLoop:
    """
    Thread-safe inbox for researcher signals.

    Parameters
    ----------
    persistent_by_default : bool
        When True, ``submit`` defaults to keeping the signal in the inbox
        after it's served. When False, the signal is removed on first match.
    """

    def __init__(self, *, persistent_by_default: bool = True) -> None:
        self._lock = threading.Lock()
        self._signals: list[HITLSignal] = []
        # Tracks which signals have been consumed when not persistent.
        self._one_shot_ids: set[str] = set()
        self._consumed_one_shot: set[str] = set()
        self.persistent_by_default = persistent_by_default

    # ------------------------------------------------------------------
    # Researcher-facing API
    # ------------------------------------------------------------------

    def mark_promising(
        self,
        *,
        sequence_id: Optional[str] = None,
        hypothesis_id: Optional[str] = None,
        fingerprint: Optional[str] = None,
        weight: float = 1.0,
        rationale: str = "",
        persistent: Optional[bool] = None,
        issued_by: str = "researcher",
    ) -> HITLSignal:
        """Inject a positive-reward signal on a specific sequence/hypothesis."""
        signal = HITLSignal(
            signal_type=HITLSignalType.PROMISING,
            target_sequence_id=sequence_id,
            target_hypothesis_id=hypothesis_id,
            target_fingerprint=fingerprint,
            weight=abs(weight),
            rationale=rationale,
            issued_by=issued_by,
        )
        self._submit(signal, persistent=persistent)
        return signal

    def mark_not_viable(
        self,
        *,
        sequence_id: Optional[str] = None,
        hypothesis_id: Optional[str] = None,
        fingerprint: Optional[str] = None,
        weight: float = 1.0,
        rationale: str = "",
        persistent: Optional[bool] = None,
        issued_by: str = "researcher",
    ) -> HITLSignal:
        """Inject a negative-reward signal — discourage further exploration."""
        signal = HITLSignal(
            signal_type=HITLSignalType.NOT_VIABLE,
            target_sequence_id=sequence_id,
            target_hypothesis_id=hypothesis_id,
            target_fingerprint=fingerprint,
            weight=abs(weight),
            rationale=rationale,
            issued_by=issued_by,
        )
        self._submit(signal, persistent=persistent)
        return signal

    def suggest_mutation(
        self,
        *,
        operator: str,
        sequence_id: Optional[str] = None,
        hypothesis_id: Optional[str] = None,
        fingerprint: Optional[str] = None,
        rationale: str = "",
        persistent: Optional[bool] = None,
        issued_by: str = "researcher",
    ) -> HITLSignal:
        """Tell the swarm to try a specific mutation operator next."""
        signal = HITLSignal(
            signal_type=HITLSignalType.SUGGESTED_MUTATION,
            target_sequence_id=sequence_id,
            target_hypothesis_id=hypothesis_id,
            target_fingerprint=fingerprint,
            suggested_mutation=operator,
            weight=1.0,
            rationale=rationale,
            issued_by=issued_by,
        )
        self._submit(signal, persistent=persistent)
        return signal

    # ------------------------------------------------------------------
    # Orchestrator-facing API
    # ------------------------------------------------------------------

    def signals_for(
        self,
        *,
        sequence_id: Optional[str] = None,
        hypothesis_id: Optional[str] = None,
        fingerprint: Optional[str] = None,
    ) -> list[HITLSignal]:
        """
        Return signals that should apply this episode. One-shot signals
        are marked consumed.
        """
        out: list[HITLSignal] = []
        with self._lock:
            for s in self._signals:
                if not self._matches(s, sequence_id=sequence_id,
                                     hypothesis_id=hypothesis_id,
                                     fingerprint=fingerprint):
                    continue
                if s.id in self._consumed_one_shot:
                    continue
                out.append(s)
                if s.id in self._one_shot_ids:
                    self._consumed_one_shot.add(s.id)
        return out

    def all_signals(self) -> list[HITLSignal]:
        with self._lock:
            return [s for s in self._signals if s.id not in self._consumed_one_shot]

    def clear(self) -> None:
        with self._lock:
            self._signals.clear()
            self._one_shot_ids.clear()
            self._consumed_one_shot.clear()

    def withdraw(self, signal_id: str) -> bool:
        with self._lock:
            for i, s in enumerate(self._signals):
                if s.id == signal_id:
                    self._signals.pop(i)
                    self._one_shot_ids.discard(signal_id)
                    self._consumed_one_shot.discard(signal_id)
                    return True
        return False

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_list(self) -> list[HITLSignal]:
        return self.all_signals()

    @classmethod
    def from_list(
        cls, signals: Iterable[HITLSignal], *, persistent_by_default: bool = True
    ) -> "HumanInTheLoop":
        hitl = cls(persistent_by_default=persistent_by_default)
        for s in signals:
            hitl._submit(s, persistent=True)
        return hitl

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _submit(self, signal: HITLSignal, *, persistent: Optional[bool]) -> None:
        is_persistent = self.persistent_by_default if persistent is None else persistent
        with self._lock:
            self._signals.append(signal)
            if not is_persistent:
                self._one_shot_ids.add(signal.id)
        logger.debug(
            "HITL signal %s submitted (type=%s, persistent=%s)",
            signal.id[:8], signal.signal_type.value, is_persistent,
        )

    @staticmethod
    def _matches(
        s: HITLSignal,
        *,
        sequence_id: Optional[str],
        hypothesis_id: Optional[str],
        fingerprint: Optional[str],
    ) -> bool:
        # An untargeted signal (no target_* fields) applies to every episode.
        if not (s.target_sequence_id or s.target_hypothesis_id or s.target_fingerprint):
            return True
        if sequence_id and s.target_sequence_id == sequence_id:
            return True
        if hypothesis_id and s.target_hypothesis_id == hypothesis_id:
            return True
        if fingerprint and s.target_fingerprint == fingerprint:
            return True
        return False
