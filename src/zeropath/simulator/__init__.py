"""
Phase 5: EVM Simulation Engine.

Executes Phase 4 :class:`TransactionSequence` objects against a Foundry/Anvil
mainnet fork, captures balance + storage deltas, decodes reverts into
mutation guidance for Phase 4, and integrates Echidna / Medusa fuzzing plus
Halmos symbolic execution against Phase 2 invariants.

Public API::

    from zeropath.simulator import SimulationOrchestrator

    orch = SimulationOrchestrator(
        fork_url=os.environ["ETH_RPC_URL"],
        fork_block=18_500_000,
        fuzzer=MedusaFuzzer(),
        halmos=HalmosChecker(),
    )
    sim_report = orch.run(seq_report, inv_report)
    for r in sim_report.profitable_results:
        print(r.profit_wei, r.sequence_id)
"""

from zeropath.simulator.anvil import AnvilError, AnvilNotAvailable, AnvilProcess
from zeropath.simulator.executor import SequenceExecutor
from zeropath.simulator.fuzzer import EchidnaFuzzer, MedusaFuzzer
from zeropath.simulator.halmos import HalmosChecker
from zeropath.simulator.models import (
    BalanceDiff,
    FuzzerKind,
    FuzzerViolation,
    HalmosCheck,
    HalmosResult,
    RevertInfo,
    SimulationOutcome,
    SimulationReport,
    SimulationResult,
    StepResult,
    StorageDiff,
)
from zeropath.simulator.revert_analyzer import RevertAnalyzer, decode_revert, suggest_mutation
from zeropath.simulator.simulator import SimulationOrchestrator
from zeropath.simulator.state_tracker import StateTracker

__all__ = [
    # Orchestrator
    "SimulationOrchestrator",
    # Components
    "AnvilProcess", "AnvilError", "AnvilNotAvailable",
    "SequenceExecutor",
    "StateTracker",
    "RevertAnalyzer", "decode_revert", "suggest_mutation",
    "EchidnaFuzzer", "MedusaFuzzer",
    "HalmosChecker",
    # Models
    "SimulationReport", "SimulationResult", "StepResult",
    "BalanceDiff", "StorageDiff", "RevertInfo",
    "FuzzerViolation", "FuzzerKind",
    "HalmosCheck", "HalmosResult",
    "SimulationOutcome",
]
