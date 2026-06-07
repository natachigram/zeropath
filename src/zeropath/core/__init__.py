"""Evidence-first research engine primitives for ZeroPath.

The modules in this package are intentionally independent from Solidity/EVM
details. Language and execution assumptions belong in adapters.
"""

from zeropath.core.schemas import (
    AdapterDetection,
    Asset,
    CandidateFinding,
    DeveloperClaim,
    EvidenceBundle,
    ExploitPattern,
    ExternalDependency,
    Impact,
    Invariant,
    JudgeResult,
    MemoryDecision,
    MemoryItem,
    ProjectConfig,
    ProtocolIntent,
    RejectionCheck,
    Role,
    SourceLocation,
    TrustBoundary,
)
from zeropath.core.storage import Storage

__all__ = [
    "AdapterDetection",
    "Asset",
    "CandidateFinding",
    "DeveloperClaim",
    "EvidenceBundle",
    "ExploitPattern",
    "ExternalDependency",
    "Impact",
    "Invariant",
    "JudgeResult",
    "MemoryDecision",
    "MemoryItem",
    "ProjectConfig",
    "ProtocolIntent",
    "RejectionCheck",
    "Role",
    "SourceLocation",
    "Storage",
    "TrustBoundary",
]
