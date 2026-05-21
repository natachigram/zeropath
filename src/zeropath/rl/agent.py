"""
RLAgent — Phase 7.

Composes a :class:`Policy` with per-episode bookkeeping and runs one episode
against an :class:`ExploitEnvironment`. The agent is single-threaded; the
:class:`PopulationManager` drives many of them in parallel.
"""

from __future__ import annotations

import logging
import time
from typing import Iterable, Optional

from zeropath.rl.environment import Action, ExploitEnvironment, State, StepResult
from zeropath.rl.models import (
    AgentSpec,
    AgentStats,
    CurriculumTier,
    Episode,
    EpisodeOutcome,
    HITLSignal,
)
from zeropath.rl.policy import Policy, StochasticPolicy
from zeropath.rl.reward import RewardInputs, RewardShaper
from zeropath.simulator.models import SimulationOutcome

logger = logging.getLogger(__name__)


class RLAgent:
    """
    One agent in the swarm — owns a policy + running stats.

    Parameters
    ----------
    spec : AgentSpec
        Hyperparameter bundle. Persisted across generations.
    policy : Policy | None
        Optional pre-built policy (e.g. from checkpoint). If None a fresh
        :class:`StochasticPolicy` is created from ``spec``.
    """

    def __init__(
        self,
        spec: AgentSpec,
        *,
        policy: Optional[Policy] = None,
    ) -> None:
        self.spec = spec
        self.policy: Policy = policy or StochasticPolicy(spec)
        self.stats = AgentStats(agent_id=spec.id, spec=spec)
        # Set[str] of state hashes this agent has seen — drives the novelty bonus.
        self._visited_states: set[str] = set()
        # Set[tuple[str,...]] of action sequences this agent has emitted —
        # drives the diversity bonus.
        self._visited_action_sequences: set[tuple[str, ...]] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_episode(
        self,
        env: ExploitEnvironment,
        *,
        reward_shaper: RewardShaper,
        hitl_signals: Iterable[HITLSignal] = (),
        curriculum_tier: CurriculumTier = CurriculumTier.SINGLE_CONTRACT_NO_ORACLE,
        seed_sequence=None,
    ) -> Episode:
        """
        Drive one episode end-to-end. Returns a fully-populated :class:`Episode`.
        """
        start = time.monotonic()
        hitl_signals = list(hitl_signals)

        # Let the policy absorb any researcher signals before acting.
        if hitl_signals and hasattr(self.policy, "absorb_hitl"):
            self.policy.absorb_hitl(hitl_signals)

        state: State = env.reset(
            seed_sequence=seed_sequence,
            curriculum_tier=curriculum_tier,
        )
        seed_id = env.seed_id or ""

        action_labels: list[str] = []
        final_step: Optional[StepResult] = None
        terminal_action: Optional[Action] = None

        while True:
            available = env.action_space
            action = self.policy.select(state, available=available)
            step_result = env.step(action)

            action_labels.append(action.label)

            # Intermediate (non-terminal) reward: small novelty credit only.
            if not step_result.done:
                novelty = 1.0 if step_result.state.state_hash not in self._visited_states else 0.0
                interim = reward_shaper.w_novelty * novelty
                self.policy.update(action, interim, terminal=False)
                self._visited_states.add(step_result.state.state_hash)
                state = step_result.state
                continue

            # Terminal step — compute the full shaped reward.
            final_step = step_result
            terminal_action = action
            break

        assert final_step is not None and terminal_action is not None

        raw = final_step.raw_signal
        seq = raw.get("sequence")
        sim = raw.get("simulation")  # SimulationResult | None

        is_novel = state.state_hash not in self._visited_states
        self._visited_states.add(state.state_hash)
        action_tuple = tuple(action_labels)
        is_unique_sequence = action_tuple not in self._visited_action_sequences
        self._visited_action_sequences.add(action_tuple)

        inputs = RewardInputs(
            profit_wei=raw.get("profit_wei", 0),
            gas_used=raw.get("gas_used", 0),
            capital_required_usd=self._capital_required(seq),
            invariant_violation_score=self._invariant_score(sim),
            state_hash=raw.get("state_hash", ""),
            is_novel_state=is_novel,
            sequence_diversity=1.0 if is_unique_sequence else 0.5,
            outcome=raw.get("outcome"),
        )
        breakdown = reward_shaper.shape(inputs, hitl_signals=hitl_signals)
        self.policy.update(terminal_action, breakdown.total, terminal=True)

        # ---------- Build Episode record ----------
        outcome = self._episode_outcome(raw)
        episode = Episode(
            agent_id=self.spec.id,
            generation=self.spec.generation,
            curriculum_tier=curriculum_tier,
            seed_sequence_id=seed_id,
            final_sequence_id=seq.id if seq else "",
            final_simulation_id=sim.id if sim else "",
            action_log=action_labels,
            outcome=outcome,
            profit_wei=raw.get("profit_wei", 0),
            gas_used=raw.get("gas_used", 0),
            reward=breakdown,
            hitl_signals_received=len(hitl_signals),
            elapsed_seconds=round(time.monotonic() - start, 3),
        )

        self._update_stats(episode)
        return episode

    # ------------------------------------------------------------------
    # Stats / serialisation
    # ------------------------------------------------------------------

    def _update_stats(self, episode: Episode) -> None:
        s = self.stats
        s.episodes += 1
        s.cumulative_reward += episode.reward.total
        if episode.reward.total > s.best_reward:
            s.best_reward = episode.reward.total
            s.best_episode_id = episode.id
        if episode.profit_wei > s.best_profit_wei:
            s.best_profit_wei = episode.profit_wei
        if episode.outcome == EpisodeOutcome.PROFITABLE:
            s.profitable_episodes += 1
        s.last_seen_generation = episode.generation
        s.novel_state_count = len(self._visited_states)

    @property
    def fitness(self) -> float:
        """
        Mean reward over all episodes this agent has run. Used by the
        population manager to rank for selection.
        """
        return self.stats.mean_reward

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _episode_outcome(raw: dict) -> EpisodeOutcome:
        kind = raw.get("kind")
        outcome: Optional[SimulationOutcome] = raw.get("outcome")
        if kind == "stop":
            return EpisodeOutcome.BUDGET_EXHAUSTED
        if raw.get("budget_exhausted"):
            return EpisodeOutcome.BUDGET_EXHAUSTED
        if outcome == SimulationOutcome.PROFITABLE:
            return EpisodeOutcome.PROFITABLE
        if outcome == SimulationOutcome.EXECUTED_NO_PROFIT:
            return EpisodeOutcome.EXECUTED_NO_PROFIT
        if outcome == SimulationOutcome.REVERTED:
            return EpisodeOutcome.REVERTED
        if outcome == SimulationOutcome.SIMULATION_ERROR:
            return EpisodeOutcome.SIM_ERROR
        return EpisodeOutcome.EXECUTED_NO_PROFIT

    @staticmethod
    def _invariant_score(sim) -> float:
        """
        Partial-credit invariant-violation score:
          * 1.0 when a Halmos check falsified an invariant
          * 0.7 when a fuzzer surfaced a property violation
          * 0.0 otherwise (or no simulation)
        """
        if sim is None:
            return 0.0
        from zeropath.simulator.models import HalmosResult
        if sim.halmos_result == HalmosResult.FALSIFIED:
            return 1.0
        if sim.fuzzer_violations:
            return 0.7
        return 0.0

    @staticmethod
    def _capital_required(sequence) -> int:
        """Capital required in USD — 0 when flash-loan-funded, else best-effort."""
        if sequence is None:
            return 0
        if sequence.uses_flash_loan:
            return 0
        if sequence.profit_estimate and sequence.profit_estimate.notes:
            # No direct USD field on ProfitEstimate; use a heuristic 1k as
            # a non-zero floor so the reward shaper has a signal to work with.
            return 1_000
        return 0
