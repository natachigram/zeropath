"""
PopulationManager — Phase 7.

Spec (phases.md, PHASE 7 critical additions, "Population-based swarm"):
    "Run a population of N agents (N=50-500 depending on compute budget)
     with different exploration strategies, specializations, random seeds.
     Use fitness-based selection: top K agents reproduce (share policy
     weights), bottom K are re-initialized with mutations. This is genetic
     algorithm + RL combined."

Responsibilities:
  * Initialise a diverse population from a target ``population_size``.
  * Rank agents by fitness (mean shaped reward).
  * Each generation: keep top K (elites), reseed bottom K with mutated
    AgentSpecs cloned from random elites.
  * Emit :class:`PopulationStats` rows so the orchestrator can plot
    swarm-level convergence.

Note: "share policy weights" in the spec assumes a neural-net policy. With
the stdlib :class:`StochasticPolicy`, weight-sharing translates to copying
the Q-value table from the elite — implemented via ``policy.from_dict``.
"""

from __future__ import annotations

import logging
import random
from typing import Iterable, Optional

from zeropath.rl.agent import RLAgent
from zeropath.rl.models import (
    AgentSpec,
    AgentStats,
    ExplorationStrategy,
    PopulationStats,
    Specialization,
)
from zeropath.rl.policy import Policy, StochasticPolicy

logger = logging.getLogger(__name__)


# Spec-derived: the swarm must cover diverse strategies/specs simultaneously.
_DEFAULT_STRATEGIES: tuple[ExplorationStrategy, ...] = (
    ExplorationStrategy.EPSILON_GREEDY,
    ExplorationStrategy.UCB,
    ExplorationStrategy.THOMPSON,
    ExplorationStrategy.SOFTMAX,
    ExplorationStrategy.PURE_RANDOM,
)

_DEFAULT_SPECIALIZATIONS: tuple[Specialization, ...] = (
    Specialization.FLASH_LOAN,
    Specialization.ORACLE_MANIPULATION,
    Specialization.REENTRANCY,
    Specialization.ACCESS_CONTROL,
    Specialization.COMPOSABILITY,
    Specialization.GOVERNANCE,
    Specialization.INTEGER_MATH,
    Specialization.GENERALIST,
)


class PopulationManager:
    """
    Maintain and evolve a swarm of :class:`RLAgent` instances.

    Parameters
    ----------
    population_size : int
        Target population size (50–500 per spec).
    elite_fraction : float
        Fraction of agents that survive into the next generation unchanged.
        Default 0.20 = top 20% are elites.
    reseed_fraction : float
        Fraction of the bottom that get re-initialised with mutated specs.
        Default 0.30. Overlap with elite_fraction is not allowed
        (``elite + reseed <= 1.0``).
    policy_factory : callable(spec) -> Policy
        Builds a policy for a given AgentSpec. Default = StochasticPolicy.
    rng_seed : int
        Master RNG seed for reproducibility.
    """

    def __init__(
        self,
        *,
        population_size: int = 20,
        elite_fraction: float = 0.20,
        reseed_fraction: float = 0.30,
        policy_factory=StochasticPolicy,
        rng_seed: int = 0,
    ) -> None:
        if elite_fraction + reseed_fraction > 1.0:
            raise ValueError("elite_fraction + reseed_fraction must be ≤ 1.0")
        self.population_size = max(2, population_size)
        self.elite_fraction = elite_fraction
        self.reseed_fraction = reseed_fraction
        self.policy_factory = policy_factory
        self._rng = random.Random(rng_seed)
        self._generation = 0
        self.agents: list[RLAgent] = []
        self.history: list[PopulationStats] = []
        self._initialise()

    # ------------------------------------------------------------------
    # Init
    # ------------------------------------------------------------------

    def _initialise(self) -> None:
        """Seed a diverse generation 0."""
        specs = self._build_initial_specs(self.population_size)
        self.agents = [RLAgent(s, policy=self.policy_factory(s)) for s in specs]
        self._snapshot()

    def _build_initial_specs(self, n: int) -> list[AgentSpec]:
        out: list[AgentSpec] = []
        for i in range(n):
            spec = AgentSpec(
                specialization=_DEFAULT_SPECIALIZATIONS[i % len(_DEFAULT_SPECIALIZATIONS)],
                exploration=_DEFAULT_STRATEGIES[i % len(_DEFAULT_STRATEGIES)],
                epsilon=round(self._rng.uniform(0.05, 0.40), 3),
                ucb_c=round(self._rng.uniform(0.5, 4.0), 3),
                softmax_temperature=round(self._rng.uniform(0.3, 2.0), 3),
                generation=0,
                seed=self._rng.randint(1, 2**31 - 1),
            )
            out.append(spec)
        return out

    # ------------------------------------------------------------------
    # Per-generation evolution
    # ------------------------------------------------------------------

    def evolve(self) -> PopulationStats:
        """
        Advance one generation: rank agents, keep elites, reseed weakest.

        Returns the :class:`PopulationStats` for the new generation. After
        this call, ``self.agents`` has size ``population_size`` again with
        ``self._generation`` incremented.
        """
        ranked = sorted(self.agents, key=lambda a: a.fitness, reverse=True)
        n = len(ranked)
        n_elite = max(1, int(n * self.elite_fraction))
        n_reseed = max(1, int(n * self.reseed_fraction))
        n_keep = n - n_reseed   # everyone but the bottom reseed_fraction survives

        elites = ranked[:n_elite]
        survivors = ranked[:n_keep]
        # Reseed slot count = original size − survivors kept.
        n_reseed_actual = n - len(survivors)

        new_specs: list[AgentSpec] = []
        new_agents: list[RLAgent] = list(survivors)
        for _ in range(n_reseed_actual):
            parent = self._rng.choice(elites)
            child_spec = self._mutate_spec(parent.spec)
            child_policy = self._build_child_policy(parent, child_spec)
            new_agents.append(RLAgent(child_spec, policy=child_policy))
            new_specs.append(child_spec)

        self.agents = new_agents
        self._generation += 1
        # Stamp the new generation onto every agent's spec for telemetry.
        for a in self.agents:
            a.spec.generation = self._generation

        return self._snapshot(elite_size=n_elite, reseeded_size=n_reseed_actual)

    # ------------------------------------------------------------------
    # Spec / policy mutation
    # ------------------------------------------------------------------

    def _mutate_spec(self, parent: AgentSpec) -> AgentSpec:
        """
        Produce a child spec by perturbing the parent's hyperparams.

        Specialization and exploration strategy stay the same most of the
        time but flip with 15% probability to drive diversity.
        """
        child = parent.model_copy()
        child.id = AgentSpec().id
        child.parent_id = parent.id
        child.generation = self._generation + 1
        child.seed = self._rng.randint(1, 2**31 - 1)

        if self._rng.random() < 0.15:
            child.exploration = self._rng.choice(_DEFAULT_STRATEGIES)
        if self._rng.random() < 0.10:
            child.specialization = self._rng.choice(_DEFAULT_SPECIALIZATIONS)

        # Gaussian perturbation, then clamp to valid range.
        child.epsilon = max(0.01, min(0.50, parent.epsilon + self._rng.gauss(0, 0.05)))
        child.ucb_c = max(0.1, min(8.0, parent.ucb_c + self._rng.gauss(0, 0.5)))
        child.softmax_temperature = max(
            0.1, min(5.0, parent.softmax_temperature + self._rng.gauss(0, 0.2))
        )
        return child

    def _build_child_policy(self, parent: RLAgent, child_spec: AgentSpec) -> Policy:
        """
        "Top performers share weights" — copy the parent's policy dict into
        the child, then rebind to the child's spec.
        """
        try:
            parent_state = parent.policy.to_dict()
            inherited = dict(parent_state)
            inherited["spec"] = child_spec.model_dump()
            return type(parent.policy).from_dict(inherited)
        except Exception:
            logger.debug("policy inheritance failed; building fresh policy")
            return self.policy_factory(child_spec)

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------

    def _snapshot(
        self, *, elite_size: int = 0, reseeded_size: int = 0,
    ) -> PopulationStats:
        fitnesses = [a.fitness for a in self.agents] or [0.0]
        best = max(self.agents, key=lambda a: a.fitness) if self.agents else None
        stats = PopulationStats(
            generation=self._generation,
            population_size=len(self.agents),
            elite_size=elite_size,
            reseeded_size=reseeded_size,
            best_fitness=max(fitnesses),
            mean_fitness=sum(fitnesses) / len(fitnesses),
            best_agent_id=best.spec.id if best else None,
            distinct_strategies=len({a.spec.exploration for a in self.agents}),
            distinct_specializations=len({a.spec.specialization for a in self.agents}),
        )
        self.history.append(stats)
        return stats

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @property
    def generation(self) -> int:
        return self._generation

    def stats(self) -> list[AgentStats]:
        return [a.stats for a in self.agents]

    def best_agent(self) -> Optional[RLAgent]:
        if not self.agents:
            return None
        return max(self.agents, key=lambda a: a.fitness)
