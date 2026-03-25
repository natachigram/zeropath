"""
Custom exception hierarchy for ZeroPath.

Every domain failure has a specific, catchable type so callers can
respond appropriately rather than catching bare Exception.
"""


class ZeropathError(Exception):
    """Base exception for all ZeroPath errors."""


class ParsingError(ZeropathError):
    """Contract source parsing failed (syntax error, bad pragma, etc.)."""


class ASTExtractionError(ZeropathError):
    """AST extraction from Slither output failed."""


class GraphConstructionError(ZeropathError):
    """Protocol graph assembly failed."""


class StorageExtractionError(ZeropathError):
    """Storage layout extraction failed."""


class AssetFlowTrackingError(ZeropathError):
    """Asset flow analysis failed."""


class ProxyDetectionError(ZeropathError):
    """Proxy pattern detection failed."""


class GraphDatabaseError(ZeropathError):
    """Neo4j operation failed (connection, query, write)."""


class ConfigurationError(ZeropathError):
    """Invalid or missing configuration."""


class VersionDiffError(ZeropathError):
    """Version diff computation failed."""


class BytecodeDecompilationError(ZeropathError):
    """Bytecode decompilation via Heimdall failed or returned unusable output."""


class GitHubIngestionError(ZeropathError):
    """GitHub repository cloning or file fetching failed."""
