"""ZeroPath package.

Package-level legacy exports are loaded lazily so lightweight evidence-first
modules can be used without importing optional graph, Neo4j, or Slither paths.
"""

from __future__ import annotations

from importlib import import_module

__version__ = "0.3.0"

from zeropath.exceptions import (  # noqa: E402
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

_LAZY_EXPORTS = {
    "ContractParser": ("zeropath.parser", "ContractParser"),
    "HeimdallDecompiler": ("zeropath.bytecode_decompiler", "HeimdallDecompiler"),
    "DecompileResult": ("zeropath.bytecode_decompiler", "DecompileResult"),
    "OnChainFetcher": ("zeropath.onchain_fetcher", "OnChainFetcher"),
    "OnChainSource": ("zeropath.onchain_fetcher", "OnChainSource"),
    "ProtocolGraphBuilder": ("zeropath.graph_builder", "ProtocolGraphBuilder"),
    "ProtocolGraph": ("zeropath.models", "ProtocolGraph"),
    "Neo4jGraphDB": ("zeropath.graph_db", "Neo4jGraphDB"),
    "Contract": ("zeropath.models", "Contract"),
    "Function": ("zeropath.models", "Function"),
    "FunctionCall": ("zeropath.models", "FunctionCall"),
    "FunctionSignature": ("zeropath.models", "FunctionSignature"),
    "Parameter": ("zeropath.models", "Parameter"),
    "StateVariable": ("zeropath.models", "StateVariable"),
    "Event": ("zeropath.models", "Event"),
    "AssetFlow": ("zeropath.models", "AssetFlow"),
    "ExternalDependency": ("zeropath.models", "ExternalDependency"),
    "ProxyRelationship": ("zeropath.models", "ProxyRelationship"),
    "VersionDiff": ("zeropath.models", "VersionDiff"),
    "Visibility": ("zeropath.models", "Visibility"),
    "ContractLanguage": ("zeropath.models", "ContractLanguage"),
    "ProxyType": ("zeropath.models", "ProxyType"),
    "SwarmOrchestrator": ("zeropath.adversarial", "SwarmOrchestrator"),
    "SwarmReport": ("zeropath.adversarial", "SwarmReport"),
    "AttackHypothesis": ("zeropath.adversarial.models", "AttackHypothesis"),
    "AttackClass": ("zeropath.adversarial.models", "AttackClass"),
}


def __getattr__(name: str):
    if name not in _LAZY_EXPORTS:
        raise AttributeError(f"module 'zeropath' has no attribute {name!r}")
    module_name, attr = _LAZY_EXPORTS[name]
    module = import_module(module_name)
    value = getattr(module, attr)
    globals()[name] = value
    return value


__all__ = [
    "__version__",
    "ContractParser",
    "HeimdallDecompiler",
    "DecompileResult",
    "OnChainFetcher",
    "OnChainSource",
    "ProtocolGraphBuilder",
    "ProtocolGraph",
    "Neo4jGraphDB",
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
    "Visibility",
    "ContractLanguage",
    "ProxyType",
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
    "SwarmOrchestrator",
    "SwarmReport",
    "AttackHypothesis",
    "AttackClass",
]
