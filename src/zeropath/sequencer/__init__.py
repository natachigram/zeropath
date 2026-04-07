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

from zeropath.sequencer.codegen import FoundryTestGenerator, HardhatScriptGenerator
from zeropath.sequencer.models import (
    AttackContext,
    CallerType,
    CallEncoding,
    GeneratedTest,
    ProfitEstimate,
    SequenceReport,
    SequenceStatus,
    TestFramework,
    TransactionSequence,
    TxCall,
)
from zeropath.sequencer.sequencer import SequenceOrchestrator

__all__ = [
    # Orchestration
    "SequenceOrchestrator",
    "FoundryTestGenerator",
    "HardhatScriptGenerator",
    # Models
    "SequenceReport",
    "TransactionSequence",
    "TxCall",
    "AttackContext",
    "GeneratedTest",
    "ProfitEstimate",
    "SequenceStatus",
    "TestFramework",
    "CallerType",
    "CallEncoding",
]
