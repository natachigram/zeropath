"""
Phase 2: Invariant Inference Engine.

Public API:

    from zeropath.invariants import InvariantInferenceEngine, InvariantReport

    engine = InvariantInferenceEngine()
    report = engine.analyse(graph, protocol_name="MyProtocol")
"""

from zeropath.invariants.engine import InvariantInferenceEngine
from zeropath.invariants.models import (
    DeFiProtocolType,
    FormalSpec,
    HistoricalPrecedent,
    Invariant,
    InvariantReport,
    InvariantSeverity,
    InvariantType,
    OracleDependency,
    OracleManipulationRisk,
    OracleType,
    ProtocolPattern,
)

__all__ = [
    # Engine
    "InvariantInferenceEngine",
    # Report models
    "InvariantReport",
    "Invariant",
    "InvariantType",
    "InvariantSeverity",
    "FormalSpec",
    "HistoricalPrecedent",
    "OracleDependency",
    "OracleType",
    "OracleManipulationRisk",
    "ProtocolPattern",
    "DeFiProtocolType",
]
