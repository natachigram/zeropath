"""
ExploitEnvironment — Phase 7 RL environment.

Spec (phases.md, PHASE 7 LLM prompt):
    "Define environment:
       state: protocol graph + current EVM state (from Phase 5 fork)
       actions: transaction sequences (from Phase 4 generator)
       reward: shaped reward (profit + invariant violation + novelty - gas - capital)"

This module turns Phase 4 + Phase 5 into a Gym-shaped (reset, step) loop the
RL agents in this package can drive. **No torch / gym dependency** — the
interface is a small dataclass-shaped record so the swarm can be exercised
in tests without any ML stack installed.

Action space
------------
At each step the agent picks one of:

  * ``("mutate", op_name)``         — apply a Phase 4 mutation operator to
                                       the current sequence (cheap, in-process).
  * ``("execute", None)``           — submit the current sequence to the
                                       Phase 5 simulator → terminal reward.
  * ``("stop", None)``              — abandon the episode (no execute).

The environment caps episodes at ``step_budget`` mutations so policies that
never call ``execute`` still terminate.

State
-----
A compact :class:`State` dataclass exposes:

  * the current ``TransactionSequence`` (so the policy can read calls / context)
  * a stable ``state_hash`` over (attack_class, target addresses, function sigs,
    rounded amount magnitudes) for novelty tracking
  * the curriculum tier
  * ``step_index`` and ``step_budget``

Simulator integration
---------------------
The env holds an optional :class:`SequenceExecutor`. When None (the default
in tests), the env uses ``StubExecutor`` which returns a synthetic
:class:`SimulationResult` derived from a deterministic hash. This lets the
swarm train against the offline mutation surface without spinning up Anvil.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional, Protocol

from zeropath.adversarial.models import AttackClass
from zeropath.sequencer.models import TransactionSequence
from zeropath.sequencer.mutation import MutationEngine
from zeropath.simulator.models import SimulationOutcome, SimulationResult
from zeropath.rl.models import CurriculumTier

logger = logging.getLogger(__name__)


# Default cap on mutations before an episode is force-terminated.
DEFAULT_STEP_BUDGET = 8


# ---------------------------------------------------------------------------
# Action + State
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Action:
    """One discrete action the agent takes against the environment."""

    kind: str           # "mutate" | "execute" | "stop"
    operator: Optional[str] = None   # mutation operator name when kind="mutate"

    @property
    def label(self) -> str:
        return self.operator and f"{self.kind}:{self.operator}" or self.kind


@dataclass
class State:
    """Snapshot the policy observes before each step."""

    sequence: TransactionSequence
    curriculum_tier: CurriculumTier
    step_index: int
    step_budget: int
    state_hash: str

    @property
    def remaining_steps(self) -> int:
        return max(0, self.step_budget - self.step_index)

    @property
    def attack_class(self) -> str:
        return self.sequence.attack_class


@dataclass
class StepResult:
    """Return value of ``ExploitEnvironment.step()``."""

    state: State
    raw_signal: dict           # raw reward inputs — RewardShaper consumes this
    done: bool = False
    info: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pluggable simulator interface
# ---------------------------------------------------------------------------


class SimulatorLike(Protocol):
    """Minimal interface the env needs. Phase 5 SequenceExecutor satisfies it."""

    def execute(self, sequence: TransactionSequence) -> SimulationResult: ...


class StubExecutor:
    """
    Deterministic synthetic executor for training without Anvil.

    Produces a fake :class:`SimulationResult` whose profit/gas depend on a
    hash of the sequence. This is *not* a substitute for real simulation —
    it exists so the population manager + reward shaper can be unit-tested
    in isolation and so the swarm can do warm-up exploration cheaply
    before swapping in the real executor.
    """

    def execute(self, sequence: TransactionSequence) -> SimulationResult:
        h = hashlib.blake2s(_sequence_signature(sequence).encode("utf-8"), digest_size=8).digest()
        seed = int.from_bytes(h, "big")
        outcome_score = (seed % 1000) / 1000.0

        # Deterministic outcome bucketing: 5% profitable, 20% revert, 75% no profit.
        if outcome_score < 0.05:
            profit_wei = (seed % (10**18)) + 10**15
            outcome = SimulationOutcome.PROFITABLE
            success = True
            revert_reason = None
        elif outcome_score < 0.25:
            profit_wei = 0
            outcome = SimulationOutcome.REVERTED
            success = False
            revert_reason = "stub: synthetic revert"
        else:
            profit_wei = 0
            outcome = SimulationOutcome.EXECUTED_NO_PROFIT
            success = True
            revert_reason = None

        gas_used = 200_000 + (seed % 600_000)

        return SimulationResult(
            sequence_id=sequence.id,
            hypothesis_id=sequence.hypothesis_id,
            success=success,
            outcome=outcome,
            profit_wei=profit_wei,
            gas_used=gas_used,
            revert_reason=revert_reason,
        )


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------


# Map attack class to the lowest curriculum tier capable of expressing it.
# Used to filter seed sequences by tier when curriculum learning is on.
_ATTACK_CLASS_TIER_FLOOR: dict[str, CurriculumTier] = {
    AttackClass.ACCESS_CONTROL.value: CurriculumTier.SINGLE_CONTRACT_NO_ORACLE,
    AttackClass.INTEGER_MATH.value: CurriculumTier.SINGLE_CONTRACT_NO_ORACLE,
    AttackClass.REENTRANCY.value: CurriculumTier.MULTI_CONTRACT,
    AttackClass.ORACLE_MANIPULATION.value: CurriculumTier.WITH_ORACLE,
    AttackClass.PRICE_MANIPULATION.value: CurriculumTier.WITH_ORACLE,
    AttackClass.FLASH_LOAN.value: CurriculumTier.WITH_FLASH_LOAN,
    AttackClass.GOVERNANCE.value: CurriculumTier.MULTI_CONTRACT,
    AttackClass.COMPOSABILITY.value: CurriculumTier.CROSS_PROTOCOL,
}


def _sequence_signature(sequence: TransactionSequence) -> str:
    """Compact stable signature for novelty hashing."""
    parts = [sequence.attack_class]
    for call in sequence.calls:
        sig = call.function_signature or ""
        addr = (call.target_address or call.target_address_expr or "")[:42]
        amount_buckets = []
        for ptype, pval in zip(call.param_types, call.params):
            if ptype.startswith("uint") and isinstance(pval, int) and pval > 0:
                # Bucket on order of magnitude so "10x" mutations are novel
                # but tiny noise doesn't pollute the hash.
                import math
                amount_buckets.append(str(int(math.log10(max(pval, 1)))))
        parts.append(f"{sig}|{addr}|{','.join(amount_buckets)}")
    return "||".join(parts)


def _state_hash(sequence: TransactionSequence) -> str:
    sig = _sequence_signature(sequence)
    return hashlib.sha256(sig.encode("utf-8")).hexdigest()[:16]


class ExploitEnvironment:
    """
    Gym-style RL environment over the (mutate, execute, stop) action space.

    Parameters
    ----------
    seed_sequences : list[TransactionSequence]
        Pool the env samples from on ``reset``. Provided by the caller (Phase 4).
    simulator : SimulatorLike | None
        Phase 5 executor. Defaults to :class:`StubExecutor` for offline runs.
    mutation_engine : MutationEngine | None
        Source of mutation operators. Defaults to a fresh engine with all ops.
    step_budget : int
        Hard cap on mutations per episode.
    """

    def __init__(
        self,
        *,
        seed_sequences: list[TransactionSequence],
        simulator: Optional[SimulatorLike] = None,
        mutation_engine: Optional[MutationEngine] = None,
        step_budget: int = DEFAULT_STEP_BUDGET,
    ) -> None:
        if not seed_sequences:
            raise ValueError("ExploitEnvironment needs at least one seed sequence")
        self.seed_sequences = list(seed_sequences)
        self.simulator = simulator or StubExecutor()
        self.mutation_engine = mutation_engine or MutationEngine(max_per_sequence=8)
        self.step_budget = step_budget

        # Filled by reset()
        self._current: Optional[TransactionSequence] = None
        self._tier: CurriculumTier = CurriculumTier.SINGLE_CONTRACT_NO_ORACLE
        self._step_index = 0
        self._seed_id: Optional[str] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def available_operators(self) -> list[str]:
        """Mutation operator names visible to the policy. Stable order."""
        return [name for (name, _) in self.mutation_engine._ops]  # noqa: SLF001

    @property
    def action_space(self) -> list[Action]:
        """All discrete actions visible to the policy."""
        ops = [Action(kind="mutate", operator=name) for name in self.available_operators]
        return ops + [Action(kind="execute"), Action(kind="stop")]

    def reset(
        self,
        *,
        seed_sequence: Optional[TransactionSequence] = None,
        curriculum_tier: CurriculumTier = CurriculumTier.SINGLE_CONTRACT_NO_ORACLE,
        rng_pick=None,
    ) -> State:
        """
        Start a new episode. If ``seed_sequence`` is None, samples from
        ``seed_sequences`` filtered by ``curriculum_tier``.
        """
        self._tier = curriculum_tier
        self._step_index = 0
        if seed_sequence is None:
            eligible = self._tier_eligible(curriculum_tier) or self.seed_sequences
            seed_sequence = (rng_pick or self._first)(eligible)
        # Deep-copy so the policy can mutate freely without polluting the pool.
        self._current = seed_sequence.model_copy(deep=True)
        self._seed_id = seed_sequence.id
        return self._build_state()

    def step(self, action: Action) -> StepResult:
        """
        Apply one action. Returns the next observation + raw reward inputs
        so :class:`RewardShaper` can compute the shaped reward.
        """
        if self._current is None:
            raise RuntimeError("ExploitEnvironment.step() called before reset()")

        if action.kind == "stop":
            return StepResult(
                state=self._build_state(),
                raw_signal=self._raw_signal_for_stop(),
                done=True,
                info={"action": action.label},
            )

        if action.kind == "execute":
            sim = self.simulator.execute(self._current)
            return StepResult(
                state=self._build_state(),
                raw_signal=self._raw_signal_for_execute(sim),
                done=True,
                info={"action": action.label, "simulation_id": sim.id, "simulation": sim},
            )

        if action.kind == "mutate":
            self._apply_mutation(action.operator)
            self._step_index += 1
            done = self._step_index >= self.step_budget
            if done:
                # Out of mutation budget without an execute: auto-execute so the
                # agent still receives some terminal signal.
                sim = self.simulator.execute(self._current)
                return StepResult(
                    state=self._build_state(),
                    raw_signal=self._raw_signal_for_execute(sim, budget_exhausted=True),
                    done=True,
                    info={"action": action.label, "auto_executed": True,
                          "simulation_id": sim.id, "simulation": sim},
                )
            return StepResult(
                state=self._build_state(),
                raw_signal=self._raw_signal_for_mutate(),
                done=False,
                info={"action": action.label},
            )

        raise ValueError(f"unknown action kind: {action.kind!r}")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _build_state(self) -> State:
        assert self._current is not None
        return State(
            sequence=self._current,
            curriculum_tier=self._tier,
            step_index=self._step_index,
            step_budget=self.step_budget,
            state_hash=_state_hash(self._current),
        )

    def _apply_mutation(self, op_name: Optional[str]) -> None:
        assert self._current is not None
        if op_name is None:
            return
        engine = MutationEngine(
            max_per_sequence=1,
            enabled_operators=[op_name],
        )
        variants = engine.mutate(self._current)
        if variants:
            self._current = variants[0]

    def _raw_signal_for_mutate(self) -> dict:
        return {
            "kind": "mutate",
            "profit_wei": 0,
            "gas_used": 0,
            "outcome": None,
            "state_hash": _state_hash(self._current) if self._current else "",
            "sequence": self._current,
        }

    def _raw_signal_for_execute(self, sim: SimulationResult, *, budget_exhausted: bool = False) -> dict:
        return {
            "kind": "execute",
            "profit_wei": sim.profit_wei,
            "gas_used": sim.gas_used,
            "outcome": sim.outcome,
            "state_hash": _state_hash(self._current) if self._current else "",
            "sequence": self._current,
            "simulation": sim,
            "budget_exhausted": budget_exhausted,
        }

    def _raw_signal_for_stop(self) -> dict:
        return {
            "kind": "stop",
            "profit_wei": 0,
            "gas_used": 0,
            "outcome": None,
            "state_hash": _state_hash(self._current) if self._current else "",
            "sequence": self._current,
        }

    def _tier_eligible(self, tier: CurriculumTier) -> list[TransactionSequence]:
        out: list[TransactionSequence] = []
        for seq in self.seed_sequences:
            floor = _ATTACK_CLASS_TIER_FLOOR.get(seq.attack_class, CurriculumTier.SINGLE_CONTRACT_NO_ORACLE)
            if int(floor) <= int(tier):
                out.append(seq)
        return out

    @staticmethod
    def _first(seqs):
        return seqs[0]

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @property
    def current_sequence(self) -> Optional[TransactionSequence]:
        return self._current

    @property
    def seed_id(self) -> Optional[str]:
        return self._seed_id
