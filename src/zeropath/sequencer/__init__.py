"""
Phase 4: Transaction Sequence Generator.

Converts Phase 3 AttackHypotheses into concrete, executable transaction
sequences with generated Foundry and Hardhat PoC test files.

Public API::

    from zeropath.sequencer import SequenceOrchestrator, SequenceReport

    orchestrator = SequenceOrchestrator()
    seq_report = orchestrator.run(swarm_report, protocol_graph)

    for seq in seq_report.ready_to_simulate:
        print(seq.foundry_test.code)
"""

from zeropath.sequencer.abi_encoder import ABIEncoder, encode_call, function_selector
from zeropath.sequencer.codegen import FoundryTestGenerator, HardhatScriptGenerator
from zeropath.sequencer.gas_estimator import GasEstimator, prune_unprofitable
from zeropath.sequencer.models import (
    AttackContext,
    CallerType,
    CallEncoding,
    GeneratedTest,
    OnChainStateSnapshot,
    ProfitEstimate,
    SequenceReport,
    SequenceStatus,
    TestFramework,
    TransactionSequence,
    TxCall,
)
from zeropath.sequencer.mutation import MutationEngine
from zeropath.sequencer.onchain_state import OnChainStateFetcher
from zeropath.sequencer.sequencer import SequenceOrchestrator

__all__ = [
    # Orchestration
    "SequenceOrchestrator",
    "FoundryTestGenerator",
    "HardhatScriptGenerator",
    # Phase 4 extensions
    "ABIEncoder",
    "encode_call",
    "function_selector",
    "OnChainStateFetcher",
    "GasEstimator",
    "prune_unprofitable",
    "MutationEngine",
    # Models
    "SequenceReport",
    "TransactionSequence",
    "TxCall",
    "AttackContext",
    "OnChainStateSnapshot",
    "GeneratedTest",
    "ProfitEstimate",
    "SequenceStatus",
    "TestFramework",
    "CallerType",
    "CallEncoding",
]
