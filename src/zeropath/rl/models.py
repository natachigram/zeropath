"""
Data models for Phase 7: Exploit Evolution Engine (Swarm RL).

The RL stack is built on top of:
  Phase 4 — TransactionSequence  (action space)
  Phase 5 — SimulationResult     (environment feedback / reward signal)
  Phase 2 — Invariant            (curriculum hints + violation rewards)

These models are pure stdlib + Pydantic; no torch / numpy required. Heavy
ML stacks plug in via the :class:`Policy` protocol in ``policy.py``.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ExplorationStrategy(str, Enum):
    """Per-agent exploration policy. Spec: 'different exploration strategies'."""

    EPSILON_GREEDY = "epsilon_greedy"
    """Pick best-known action with probability 1-ε, else uniform random."""

    UCB = "ucb"
    """Upper-Confidence-Bound: choose action maximising mean + c·sqrt(ln(t)/n)."""

    THOMPSON = "thompson"
    """Thompson sampling: draw from a per-action Beta posterior, act greedily."""

    SOFTMAX = "softmax"
    """Boltzmann/softmax over Q-values with temperature τ."""

    PURE_RANDOM = "pure_random"
    """Useful as a control baseline."""


class Specialization(str, Enum):
    """
    Per-agent attack-class focus. Mirrors Phase 3 adversarial agents so the
    swarm covers the same attack surface but at the RL exploration layer.
    """

    FLASH_LOAN = "flash_loan"
    ORACLE_MANIPULATION = "oracle_manipulation"
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    COMPOSABILITY = "composability"
    GOVERNANCE = "governance"
    INTEGER_MATH = "integer_math"
    GENERALIST = "generalist"
    """No attack-class bias; weights all actions equally."""


class CurriculumTier(int, Enum):
    """Increasing protocol complexity tiers. Spec: 'simple protocols first'."""

    SINGLE_CONTRACT_NO_ORACLE = 0
    MULTI_CONTRACT = 1
    WITH_ORACLE = 2
    WITH_FLASH_LOAN = 3
    CROSS_PROTOCOL = 4


class HITLSignalType(str, Enum):
    """Researcher-provided signal types per spec."""

    PROMISING = "promising"
    NOT_VIABLE = "not_viable"
    SUGGESTED_MUTATION = "suggested_mutation"


class EpisodeOutcome(str, Enum):
    """Coarse outcome of one episode (one execute-action)."""

    PROFITABLE = "profitable"
    EXECUTED_NO_PROFIT = "executed_no_profit"
    REVERTED = "reverted"
    BUDGET_EXHAUSTED = "budget_exhausted"
    SIM_ERROR = "sim_error"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class RewardBreakdown(BaseModel):
    """Per-episode decomposition of the shaped reward. Matches spec formula."""

    model_config = ConfigDict(populate_by_name=True)

    profit_term: float = 0.0
    invariant_term: float = 0.0
    novelty_term: float = 0.0
    diversity_term: float = 0.0
    gas_term: float = 0.0
    capital_term: float = 0.0
    hitl_term: float = 0.0
    total: float = 0.0

    @property
    def positive_total(self) -> float:
        return (
            self.profit_term + self.invariant_term + self.novelty_term
            + self.diversity_term + self.hitl_term
        )


class AgentSpec(BaseModel):
    """
    Configuration for one RL agent in the swarm.

    Tweaked by :class:`PopulationManager` during fitness-based reproduction.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    specialization: Specialization = Specialization.GENERALIST
    exploration: ExplorationStrategy = ExplorationStrategy.EPSILON_GREEDY

    # Strategy hyperparameters
    epsilon: float = Field(0.20, ge=0.0, le=1.0)
    ucb_c: float = Field(2.0, ge=0.0, le=10.0)
    softmax_temperature: float = Field(1.0, gt=0.0, le=10.0)

    # Replication metadata
    parent_id: Optional[str] = None
    generation: int = 0
    seed: int = 0


class Episode(BaseModel):
    """
    One agent ↔ environment interaction sequence ending in an `execute`
    action that submits a TransactionSequence to the Phase 5 simulator.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    agent_id: str
    generation: int = 0
    curriculum_tier: CurriculumTier = CurriculumTier.SINGLE_CONTRACT_NO_ORACLE

    seed_sequence_id: str = ""
    final_sequence_id: str = ""
    final_simulation_id: str = ""

    action_log: list[str] = Field(
        default_factory=list,
        description=(
            "Ordered list of action labels chosen this episode "
            "(e.g. 'mutate:scale_amount_10x', 'execute')."
        ),
    )
    outcome: EpisodeOutcome = EpisodeOutcome.EXECUTED_NO_PROFIT
    profit_wei: int = 0
    gas_used: int = 0
    reward: RewardBreakdown = Field(default_factory=RewardBreakdown)
    hitl_signals_received: int = 0

    elapsed_seconds: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentStats(BaseModel):
    """Running per-agent telemetry, used by the population manager."""

    model_config = ConfigDict(populate_by_name=True)

    agent_id: str
    spec: AgentSpec
    episodes: int = 0
    cumulative_reward: float = 0.0
    best_reward: float = 0.0
    best_episode_id: Optional[str] = None
    best_profit_wei: int = 0
    profitable_episodes: int = 0
    novel_state_count: int = 0
    last_seen_generation: int = 0

    @property
    def mean_reward(self) -> float:
        return self.cumulative_reward / self.episodes if self.episodes else 0.0


class PopulationStats(BaseModel):
    """One row per generation — the swarm's evolution telemetry."""

    model_config = ConfigDict(populate_by_name=True)

    generation: int = 0
    population_size: int = 0
    elite_size: int = 0
    reseeded_size: int = 0
    best_fitness: float = 0.0
    mean_fitness: float = 0.0
    best_agent_id: Optional[str] = None
    curriculum_tier: CurriculumTier = CurriculumTier.SINGLE_CONTRACT_NO_ORACLE
    distinct_strategies: int = 0
    distinct_specializations: int = 0


class HITLSignal(BaseModel):
    """One researcher-provided guidance signal."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    signal_type: HITLSignalType
    target_sequence_id: Optional[str] = None
    target_hypothesis_id: Optional[str] = None
    target_fingerprint: Optional[str] = None
    weight: float = Field(
        1.0, ge=-5.0, le=5.0,
        description=(
            "Reward multiplier injected into the shaped reward when this "
            "signal applies. PROMISING typically > 0, NOT_VIABLE < 0."
        ),
    )
    suggested_mutation: Optional[str] = Field(
        None,
        description="When signal_type is SUGGESTED_MUTATION, name of the mutation operator.",
    )
    rationale: str = ""
    issued_by: str = "researcher"


# ---------------------------------------------------------------------------
# Training state (root persistence unit for checkpointing)
# ---------------------------------------------------------------------------


class TrainingState(BaseModel):
    """
    Full snapshot of one training run. Round-trips through JSON for resume.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    protocol_name: str = "unknown"
    generation: int = 0
    total_episodes: int = 0
    curriculum_tier: CurriculumTier = CurriculumTier.SINGLE_CONTRACT_NO_ORACLE

    population: list[AgentSpec] = Field(default_factory=list)
    agent_stats: list[AgentStats] = Field(default_factory=list)
    generation_history: list[PopulationStats] = Field(default_factory=list)

    # Reward-shaping novelty bookkeeping (set of state-hash strings).
    visited_state_hashes: list[str] = Field(default_factory=list)
    visited_action_sequences: list[str] = Field(default_factory=list)

    # HITL inbox snapshot.
    hitl_signals: list[HITLSignal] = Field(default_factory=list)

    # Reproducibility
    rng_seed: int = 0
    notes: str = ""


# ---------------------------------------------------------------------------
# Training report (root output of trainer.run())
# ---------------------------------------------------------------------------


class TrainingReport(BaseModel):
    """Aggregate result of one ``trainer.run()`` invocation."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    protocol_name: str = "unknown"
    state: TrainingState = Field(default_factory=TrainingState)
    episodes: list[Episode] = Field(default_factory=list)
    discovered_sequence_ids: list[str] = Field(
        default_factory=list,
        description="Sequence IDs that hit PROFITABLE — surface to Phase 6 / 8.",
    )
    analysis_metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def profitable_episodes(self) -> list[Episode]:
        return [e for e in self.episodes if e.outcome == EpisodeOutcome.PROFITABLE]

    @property
    def best_episode(self) -> Optional[Episode]:
        if not self.episodes:
            return None
        return max(self.episodes, key=lambda e: e.reward.total)
