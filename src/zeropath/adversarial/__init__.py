"""
Phase 3: Adversarial Attack Hypothesis Swarm.

Public API:

    from zeropath.adversarial import SwarmOrchestrator, SwarmReport

    swarm = SwarmOrchestrator()
    report = swarm.run(invariant_report, protocol_graph)
"""

from zeropath.adversarial.consensus import ConsensusAggregator
from zeropath.adversarial.debate import DebateEngine
from zeropath.adversarial.models import (
    AttackClass,
    AttackHypothesis,
    AttackStep,
    ConditionType,
    DebateNote,
    DebateRound,
    HypothesisStatus,
    Precondition,
    ProfitMechanism,
    SwarmReport,
)
from zeropath.adversarial.swarm import SwarmOrchestrator

__all__ = [
    # Orchestration
    "SwarmOrchestrator",
    "DebateEngine",
    "ConsensusAggregator",
    # Models
    "SwarmReport",
    "AttackHypothesis",
    "AttackStep",
    "AttackClass",
    "HypothesisStatus",
    "ConditionType",
    "Precondition",
    "ProfitMechanism",
    "DebateNote",
    "DebateRound",
]
