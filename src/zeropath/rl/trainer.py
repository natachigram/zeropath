"""
TrainingOrchestrator — Phase 7 top-level coordinator.

Pipeline per generation::

    For each agent in population:
        pull HITL signals targeted at this agent's seed sequence
        run one episode against ExploitEnvironment
        record reward / outcome → curriculum scheduler
    Curriculum: maybe promote tier
    PopulationManager: maybe evolve (selection + reseed)
    CheckpointManager: persist if interval reached
"""

from __future__ import annotations

import logging
import random
import time
from pathlib import Path
from typing import Iterable, Optional

from zeropath.sequencer.models import TransactionSequence
from zeropath.rl.agent import RLAgent
from zeropath.rl.checkpoint import CheckpointManager
from zeropath.rl.curriculum import CurriculumScheduler
from zeropath.rl.environment import ExploitEnvironment, SimulatorLike
from zeropath.rl.hitl import HumanInTheLoop
from zeropath.rl.models import (
    CurriculumTier,
    Episode,
    EpisodeOutcome,
    PopulationStats,
    TrainingReport,
    TrainingState,
)
from zeropath.rl.population import PopulationManager
from zeropath.rl.reward import RewardShaper
from zeropath.sequencer.mutation import MutationEngine

logger = logging.getLogger(__name__)


class TrainingOrchestrator:
    """
    Drive the swarm against a Phase 4 sequence pool.

    Parameters
    ----------
    seed_sequences : list[TransactionSequence]
        Pool to sample from on each episode (typically from a Phase 4 run).
    simulator : SimulatorLike | None
        Phase 5 executor; ``None`` → :class:`StubExecutor` for offline training.
    population : PopulationManager | None
        Pre-built population. ``None`` builds the default size-20 swarm.
    curriculum : CurriculumScheduler | None
    hitl : HumanInTheLoop | None
    reward_shaper : RewardShaper | None
    checkpoint_manager : CheckpointManager | None
    checkpoint_interval_episodes : int
        Save every N total episodes. 0 disables checkpointing.
    rng_seed : int
        Master RNG for sequence sampling.
    """

    def __init__(
        self,
        *,
        seed_sequences: list[TransactionSequence],
        simulator: Optional[SimulatorLike] = None,
        population: Optional[PopulationManager] = None,
        curriculum: Optional[CurriculumScheduler] = None,
        hitl: Optional[HumanInTheLoop] = None,
        reward_shaper: Optional[RewardShaper] = None,
        checkpoint_manager: Optional[CheckpointManager] = None,
        checkpoint_interval_episodes: int = 0,
        rng_seed: int = 0,
        mutation_engine: Optional[MutationEngine] = None,
        step_budget: int = 6,
        protocol_name: str = "unknown",
    ) -> None:
        if not seed_sequences:
            raise ValueError("TrainingOrchestrator needs at least one seed sequence")

        self.protocol_name = protocol_name
        self.seed_sequences = list(seed_sequences)
        self.env = ExploitEnvironment(
            seed_sequences=self.seed_sequences,
            simulator=simulator,
            mutation_engine=mutation_engine,
            step_budget=step_budget,
        )
        self.population = population or PopulationManager(rng_seed=rng_seed)
        self.curriculum = curriculum or CurriculumScheduler()
        self.hitl = hitl or HumanInTheLoop()
        self.reward_shaper = reward_shaper or RewardShaper()
        self.checkpoint_manager = checkpoint_manager
        self.checkpoint_interval_episodes = max(0, checkpoint_interval_episodes)
        self._rng = random.Random(rng_seed)
        self.rng_seed = rng_seed
        self._total_episodes = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        *,
        generations: int = 1,
        episodes_per_agent: int = 1,
        evolve_after_each_generation: bool = True,
    ) -> TrainingReport:
        """
        Run ``generations × episodes_per_agent`` episodes for each agent
        in the population, evolving between generations.
        """
        start = time.monotonic()
        report = TrainingReport(protocol_name=self.protocol_name)

        for gen in range(generations):
            gen_episodes = self._run_generation(episodes_per_agent=episodes_per_agent)
            report.episodes.extend(gen_episodes)
            for ep in gen_episodes:
                if ep.outcome == EpisodeOutcome.PROFITABLE:
                    report.discovered_sequence_ids.append(ep.final_sequence_id)

            self.curriculum.record_episodes(gen_episodes)
            promoted = self.curriculum.maybe_promote()

            if evolve_after_each_generation and gen + 1 < generations:
                stats: PopulationStats = self.population.evolve()
                stats.curriculum_tier = self.curriculum.tier

            self._maybe_checkpoint()
            logger.info(
                "Gen %d: episodes=%d, profitable=%d, tier=%s, promoted=%s",
                gen, len(gen_episodes),
                sum(1 for e in gen_episodes if e.outcome == EpisodeOutcome.PROFITABLE),
                self.curriculum.tier.name,
                promoted,
            )

        report.state = self._snapshot_state()
        report.analysis_metadata = {
            "elapsed_seconds": round(time.monotonic() - start, 3),
            "generations": generations,
            "episodes_per_agent": episodes_per_agent,
            "total_episodes": self._total_episodes,
            "final_curriculum_tier": self.curriculum.tier.value,
            "population_size": len(self.population.agents),
            "discovered_count": len(report.discovered_sequence_ids),
        }
        return report

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _run_generation(self, *, episodes_per_agent: int) -> list[Episode]:
        episodes: list[Episode] = []
        for agent in self.population.agents:
            for _ in range(episodes_per_agent):
                ep = self._run_one_episode(agent)
                episodes.append(ep)
                self._total_episodes += 1
        return episodes

    def _run_one_episode(self, agent: RLAgent) -> Episode:
        seed = self._pick_seed()
        # Pre-fetch any HITL signals targeting this seed/hypothesis.
        signals = self.hitl.signals_for(
            sequence_id=seed.id,
            hypothesis_id=seed.hypothesis_id,
        )
        return agent.run_episode(
            self.env,
            reward_shaper=self.reward_shaper,
            hitl_signals=signals,
            curriculum_tier=self.curriculum.tier,
            seed_sequence=seed,
        )

    def _pick_seed(self) -> TransactionSequence:
        # Eligible by curriculum tier first; fall back to the full pool if
        # no eligible seeds exist (early curriculum but only complex seeds).
        eligible = self.env._tier_eligible(self.curriculum.tier)  # noqa: SLF001
        if not eligible:
            eligible = self.seed_sequences
        return self._rng.choice(eligible)

    def _maybe_checkpoint(self) -> None:
        if self.checkpoint_manager is None or self.checkpoint_interval_episodes <= 0:
            return
        if self._total_episodes % self.checkpoint_interval_episodes != 0:
            return
        self.checkpoint_manager.save(
            population=self.population,
            curriculum=self.curriculum,
            hitl=self.hitl,
            total_episodes=self._total_episodes,
            rng_seed=self.rng_seed,
            protocol_name=self.protocol_name,
        )

    def _snapshot_state(self) -> TrainingState:
        return TrainingState(
            protocol_name=self.protocol_name,
            generation=self.population.generation,
            total_episodes=self._total_episodes,
            curriculum_tier=self.curriculum.tier,
            population=[a.spec for a in self.population.agents],
            agent_stats=[a.stats for a in self.population.agents],
            generation_history=list(self.population.history),
            hitl_signals=self.hitl.all_signals(),
            rng_seed=self.rng_seed,
        )
