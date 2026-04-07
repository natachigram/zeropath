"""
ZeroPath — Production-grade smart contract analyzer.

Phase 1: Protocol Ingestion + Graph Builder
Phase 2: Invariant Inference Engine
Phase 3: Adversarial Attack Hypothesis Swarm

Public API::

    from zeropath import ProtocolGraphBuilder, ProtocolGraph, Neo4jGraphDB
    from zeropath.invariants import InvariantInferenceEngine
    from zeropath.adversarial import SwarmOrchestrator

    builder = ProtocolGraphBuilder()
    graph = builder.build_from_directory(Path("contracts/"))

    inv_engine = InvariantInferenceEngine()
    inv_report = inv_engine.analyse(graph, protocol_name="MyProtocol")

    swarm = SwarmOrchestrator()
    attack_report = swarm.run(inv_report, graph)
"""

__version__ = "0.3.0"

from zeropath.exceptions import (
    ASTExtractionError,
    AssetFlowTrackingError,
    BytecodeDecompilationError,
    ConfigurationError,
    GitHubIngestionError,
    GraphConstructionError,
    GraphDatabaseError,
    ParsingError,
    ProxyDetectionError,
    StorageExtractionError,
    VersionDiffError,
    ZeropathError,
)
from zeropath.graph_builder import ProtocolGraphBuilder
from zeropath.graph_db import Neo4jGraphDB
from zeropath.models import (
    AssetFlow,
    Contract,
    ContractLanguage,
    Event,
    ExternalDependency,
    Function,
    FunctionCall,
    FunctionSignature,
    Parameter,
    ProtocolGraph,
    ProxyRelationship,
    ProxyType,
    StateVariable,
    VersionDiff,
    Visibility,
)
from zeropath.bytecode_decompiler import DecompileResult, HeimdallDecompiler
from zeropath.onchain_fetcher import OnChainFetcher, OnChainSource
from zeropath.parser import ContractParser
from zeropath.adversarial import SwarmOrchestrator, SwarmReport
from zeropath.adversarial.models import AttackHypothesis, AttackClass

__all__ = [
    # Version
    "__version__",
    # Core builder + DB
    "ContractParser",
    "HeimdallDecompiler",
    "DecompileResult",
    "OnChainFetcher",
    "OnChainSource",
    "ProtocolGraphBuilder",
    "ProtocolGraph",
    "Neo4jGraphDB",
    # Models
    "Contract",
    "Function",
    "FunctionCall",
    "FunctionSignature",
    "Parameter",
    "StateVariable",
    "Event",
    "AssetFlow",
    "ExternalDependency",
    "ProxyRelationship",
    "VersionDiff",
    # Enums
    "Visibility",
    "ContractLanguage",
    "ProxyType",
    # Exceptions
    "ZeropathError",
    "ParsingError",
    "ASTExtractionError",
    "GraphConstructionError",
    "StorageExtractionError",
    "AssetFlowTrackingError",
    "ProxyDetectionError",
    "GraphDatabaseError",
    "ConfigurationError",
    "VersionDiffError",
    "BytecodeDecompilationError",
    "GitHubIngestionError",
    # Phase 3 — Adversarial Swarm
    "SwarmOrchestrator",
    "SwarmReport",
    "AttackHypothesis",
    "AttackClass",
]
