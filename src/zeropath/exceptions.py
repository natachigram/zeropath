"""
Custom exceptions for the zeropath application.
"""


class ZeropathError(Exception):
    """Base exception for all zeropath errors."""
    pass


class ParsingError(ZeropathError):
    """Raised when contract parsing fails."""
    pass


class ASTExtractionError(ZeropathError):
    """Raised when AST extraction fails."""
    pass


class GraphConstructionError(ZeropathError):
    """Raised when protocol graph construction fails."""
    pass


class StorageExtractionError(ZeropathError):
    """Raised when storage layout extraction fails."""
    pass


class AssetFlowTrackingError(ZeropathError):
    """Raised when asset flow tracking fails."""
    pass


class GraphDatabaseError(ZeropathError):
    """Raised when graph database operations fail."""
    pass


class ConfigurationError(ZeropathError):
    """Raised when configuration is invalid."""
    pass
