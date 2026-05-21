"""
Phase 7: Exploit Evolution Engine (Swarm RL).

Population-based reinforcement learning over the Phase 4 mutation surface,
driven by Phase 5 simulation feedback through a shaped reward function.

The default :class:`StochasticPolicy` is pure-stdlib and requires no torch
install. Drop in a PyTorch PPO / SAC policy by implementing the
:class:`Policy` protocol — no other module needs to change.

Public API::

    from zeropath.rl import TrainingOrchestrator, RewardShaper, HumanInTheLoop

    orch = TrainingOrchestrator(
        seed_sequences=seq_report.sequences,
        simulator=executor,            # Phase 5 SequenceExecutor or None for stub
    )
    report = orch.run(generations=10, episodes_per_agent=3)
    for ep in report.profitable_episodes:
        print(ep.final_sequence_id, ep.profit_wei)
"""

from zeropath.rl.agent import RLAgent
from zeropath.rl.checkpoint import CheckpointError, CheckpointManager
from zeropath.rl.curriculum import CurriculumScheduler
from zeropath.rl.environment import (
    Action,
    ExploitEnvironment,
    State,
    StepResult,
    StubExecutor,
)
from zeropath.rl.hitl import HumanInTheLoop
from zeropath.rl.models import (
    AgentSpec,
    AgentStats,
    CurriculumTier,
    Episode,
    EpisodeOutcome,
    ExplorationStrategy,
    HITLSignal,
    HITLSignalType,
    PopulationStats,
    RewardBreakdown,
    Specialization,
    TrainingReport,
    TrainingState,
)
from zeropath.rl.policy import Policy, StochasticPolicy
from zeropath.rl.population import PopulationManager
from zeropath.rl.reward import RewardInputs, RewardShaper
from zeropath.rl.trainer import TrainingOrchestrator

__all__ = [
    # Orchestrator
    "TrainingOrchestrator",
    # Components
    "ExploitEnvironment", "Action", "State", "StepResult", "StubExecutor",
    "RewardShaper", "RewardInputs",
    "Policy", "StochasticPolicy",
    "RLAgent",
    "PopulationManager",
    "CurriculumScheduler",
    "HumanInTheLoop",
    "CheckpointManager", "CheckpointError",
    # Models
    "AgentSpec", "AgentStats", "Episode", "EpisodeOutcome",
    "TrainingState", "TrainingReport",
    "ExplorationStrategy", "Specialization", "CurriculumTier",
    "HITLSignal", "HITLSignalType",
    "PopulationStats", "RewardBreakdown",
]
