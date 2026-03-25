"""
ZeroPath — Production-grade smart contract analyzer.

Phase 1: Protocol Ingestion + Graph Builder

Public API::

    from zeropath import ProtocolGraphBuilder, ProtocolGraph, Neo4jGraphDB

    builder = ProtocolGraphBuilder()
    graph = builder.build_from_directory(Path("contracts/"))

    with Neo4jGraphDB(uri=..., username=..., password=...) as db:
        db.store_protocol_graph(graph)
"""

__version__ = "0.2.0"

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
from zeropath.parser import ContractParser

__all__ = [
    # Version
    "__version__",
    # Core builder + DB
    "ContractParser",
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
]
