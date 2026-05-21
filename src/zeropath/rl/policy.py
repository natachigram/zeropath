"""
Pluggable policies — Phase 7.

Defines the :class:`Policy` protocol the :class:`PopulationManager` drives,
plus a default pure-stdlib :class:`StochasticPolicy` implementing the four
spec exploration strategies (epsilon-greedy, UCB, Thompson sampling,
softmax) and a pure-random control baseline.

A PyTorch PPO / SAC policy can be dropped in by implementing the same
protocol — no other Phase 7 code needs to change.
"""

from __future__ import annotations

import math
import random
from typing import Iterable, Optional, Protocol

from zeropath.rl.environment import Action, State
from zeropath.rl.models import (
    AgentSpec,
    ExplorationStrategy,
    HITLSignal,
    HITLSignalType,
    Specialization,
)


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


class Policy(Protocol):
    """
    Minimal interface a policy must expose for the swarm to drive it.

    A policy is *stateful per agent*: it owns the Q-values / posteriors for
    its agent's exploration strategy and is updated each episode. Persist
    via :class:`CheckpointManager`.
    """

    spec: AgentSpec

    def select(self, state: State, *, available: list[Action]) -> Action: ...
    def update(self, action: Action, reward: float, terminal: bool) -> None: ...
    def to_dict(self) -> dict: ...
    @classmethod
    def from_dict(cls, data: dict) -> "Policy": ...


# ---------------------------------------------------------------------------
# Specialization → mutation operator affinity
# ---------------------------------------------------------------------------


# Per-class biases used to seed Q-values so a specialist warms up faster
# on operators that target its attack class.
_SPECIALIZATION_AFFINITY: dict[Specialization, tuple[str, ...]] = {
    Specialization.FLASH_LOAN:        ("substitute_balancer", "substitute_maker", "scale_amount_10x"),
    Specialization.ORACLE_MANIPULATION: ("repeat_manipulation", "scale_amount_100x"),
    Specialization.COMPOSABILITY:     ("substitute_balancer", "substitute_maker", "reorder_inner_steps"),
    Specialization.GOVERNANCE:        ("reorder_inner_steps",),
    Specialization.INTEGER_MATH:      ("scale_amount_1000x", "scale_amount_100x"),
    Specialization.REENTRANCY:        ("reorder_inner_steps", "repeat_manipulation"),
    Specialization.ACCESS_CONTROL:    ("reorder_inner_steps",),
    Specialization.GENERALIST:        (),
}


# ---------------------------------------------------------------------------
# Default stochastic policy
# ---------------------------------------------------------------------------


class StochasticPolicy:
    """
    Reference policy covering the four spec exploration strategies plus a
    pure-random control. Maintains per-action ``mean_reward`` + ``count``
    tables; the strategy decides how to pick from them.

    Designed for clarity and stdlib-only operation, not maximum sample
    efficiency. Swap in a torch policy for the real workload.
    """

    def __init__(
        self,
        spec: AgentSpec,
        *,
        action_labels: Optional[Iterable[str]] = None,
        initial_q: float = 0.0,
        affinity_bonus: float = 0.5,
    ) -> None:
        self.spec = spec
        self._rng = random.Random(spec.seed or random.randint(0, 2**31 - 1))
        self._counts: dict[str, int] = {}
        self._means: dict[str, float] = {}
        self._initial_q = initial_q
        self._affinity_bonus = affinity_bonus
        self._t = 0
        self._suggested_actions: list[str] = []   # HITL suggestions consumed FIFO
        if action_labels:
            for lbl in action_labels:
                self._seed_action(lbl)

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------

    def select(self, state: State, *, available: list[Action]) -> Action:
        labels = [a.label for a in available]
        # Seed any never-seen action so Q tables are consistent.
        for lbl in labels:
            if lbl not in self._counts:
                self._seed_action(lbl)

        # HITL suggestion takes priority when its action is still available.
        while self._suggested_actions:
            suggestion = self._suggested_actions.pop(0)
            if suggestion in labels:
                return next(a for a in available if a.label == suggestion)

        self._t += 1
        strat = self.spec.exploration

        if strat == ExplorationStrategy.PURE_RANDOM:
            return self._rng.choice(available)

        if strat == ExplorationStrategy.EPSILON_GREEDY:
            if self._rng.random() < self.spec.epsilon:
                return self._rng.choice(available)
            return self._argmax_action(available)

        if strat == ExplorationStrategy.UCB:
            return self._ucb_action(available)

        if strat == ExplorationStrategy.THOMPSON:
            return self._thompson_action(available)

        if strat == ExplorationStrategy.SOFTMAX:
            return self._softmax_action(available)

        # Unknown strategy → safe fallback.
        return self._rng.choice(available)

    # ------------------------------------------------------------------
    # Learning update
    # ------------------------------------------------------------------

    def update(self, action: Action, reward: float, terminal: bool) -> None:
        """
        Incremental sample-mean update. Terminal flag is currently informational
        (kept on the protocol for torch policies that distinguish bootstrap).
        """
        lbl = action.label
        n = self._counts.get(lbl, 0) + 1
        prev = self._means.get(lbl, self._initial_q)
        # Online running mean update.
        new_mean = prev + (reward - prev) / n
        self._counts[lbl] = n
        self._means[lbl] = new_mean

    # ------------------------------------------------------------------
    # HITL plumbing
    # ------------------------------------------------------------------

    def absorb_hitl(self, signals: Iterable[HITLSignal]) -> None:
        """
        Apply researcher signals to the policy. PROMISING / NOT_VIABLE
        signals nudge the action's mean directly; SUGGESTED_MUTATION
        queues the operator for the next selection.
        """
        for s in signals:
            if s.signal_type == HITLSignalType.SUGGESTED_MUTATION and s.suggested_mutation:
                self._suggested_actions.append(f"mutate:{s.suggested_mutation}")
                continue
            if s.signal_type in (HITLSignalType.PROMISING, HITLSignalType.NOT_VIABLE):
                # Coarse: bump every known action's mean by a small shift
                # weighted by signal weight. The intent is "this whole
                # direction is good/bad", not per-operator surgery.
                shift = s.weight * (0.1 if s.signal_type == HITLSignalType.PROMISING else -0.2)
                for lbl in list(self._means.keys()):
                    self._means[lbl] = self._means[lbl] + shift

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "spec": self.spec.model_dump(),
            "counts": dict(self._counts),
            "means": dict(self._means),
            "t": self._t,
            "initial_q": self._initial_q,
            "affinity_bonus": self._affinity_bonus,
            "suggested_actions": list(self._suggested_actions),
            "rng_state_seed": self.spec.seed,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "StochasticPolicy":
        spec = AgentSpec.model_validate(data["spec"])
        p = cls(
            spec,
            initial_q=data.get("initial_q", 0.0),
            affinity_bonus=data.get("affinity_bonus", 0.5),
        )
        p._counts = dict(data.get("counts", {}))
        p._means = dict(data.get("means", {}))
        p._t = data.get("t", 0)
        p._suggested_actions = list(data.get("suggested_actions", []))
        return p

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @property
    def action_counts(self) -> dict[str, int]:
        return dict(self._counts)

    @property
    def action_means(self) -> dict[str, float]:
        return dict(self._means)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _seed_action(self, label: str) -> None:
        # Apply specialization affinity to mutate:<op> actions.
        bonus = 0.0
        if label.startswith("mutate:"):
            op = label.split(":", 1)[1]
            if op in _SPECIALIZATION_AFFINITY.get(self.spec.specialization, ()):
                bonus = self._affinity_bonus
        self._means.setdefault(label, self._initial_q + bonus)
        self._counts.setdefault(label, 0)

    def _argmax_action(self, available: list[Action]) -> Action:
        best, best_q = available[0], -math.inf
        for a in available:
            q = self._means.get(a.label, self._initial_q)
            if q > best_q:
                best, best_q = a, q
        return best

    def _ucb_action(self, available: list[Action]) -> Action:
        best, best_score = available[0], -math.inf
        c = self.spec.ucb_c
        for a in available:
            n = self._counts.get(a.label, 0)
            mean = self._means.get(a.label, self._initial_q)
            if n == 0:
                score = math.inf  # force exploration of unvisited actions
            else:
                score = mean + c * math.sqrt(math.log(max(self._t, 1)) / n)
            if score > best_score:
                best, best_score = a, score
        return best

    def _thompson_action(self, available: list[Action]) -> Action:
        # Map mean ∈ [-2, 2] → α, β of a Beta(α, β) by treating
        # ((mean+2)/4) as the success prior, scaled by visit count.
        best, best_draw = available[0], -math.inf
        for a in available:
            n = self._counts.get(a.label, 0)
            mean = self._means.get(a.label, self._initial_q)
            mean01 = max(0.0, min(1.0, (mean + 2) / 4))
            # Add 1 to both so the prior is uniform Beta(1,1) at n=0.
            alpha = 1 + mean01 * n
            beta = 1 + (1 - mean01) * n
            draw = self._rng.betavariate(alpha, beta)
            if draw > best_draw:
                best, best_draw = a, draw
        return best

    def _softmax_action(self, available: list[Action]) -> Action:
        tau = max(1e-6, self.spec.softmax_temperature)
        qs = [self._means.get(a.label, self._initial_q) / tau for a in available]
        # Numerically stable softmax.
        max_q = max(qs)
        exps = [math.exp(q - max_q) for q in qs]
        s = sum(exps) or 1.0
        probs = [e / s for e in exps]
        r = self._rng.random()
        c = 0.0
        for a, p in zip(available, probs):
            c += p
            if r <= c:
                return a
        return available[-1]
