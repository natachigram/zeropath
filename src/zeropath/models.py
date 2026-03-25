"""
Core data models for the ZeroPath protocol graph.

All models are Pydantic v2 with strict typing, alias support for JSON
serialization, and full populate_by_name for internal access.
"""

from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ContractLanguage(str, Enum):
    """Source language of a contract."""

    SOLIDITY = "solidity"
    VYPER = "vyper"
    UNKNOWN = "unknown"


class Visibility(str, Enum):
    """Function or variable visibility level."""

    PUBLIC = "public"
    PRIVATE = "private"
    INTERNAL = "internal"
    EXTERNAL = "external"


class StateVariableType(str, Enum):
    """High-level type category for a state variable."""

    PRIMITIVE = "primitive"
    MAPPING = "mapping"
    ARRAY = "array"
    STRUCT = "struct"
    ADDRESS = "address"
    BYTES = "bytes"
    STRING = "string"
    ENUM = "enum"


class CallType(str, Enum):
    """Type of a function call relationship."""

    INTERNAL = "internal"
    EXTERNAL = "external"
    DELEGATECALL = "delegatecall"
    STATICCALL = "staticcall"
    LOW_LEVEL = "low_level"
    LIBRARY = "library"


class AccessType(str, Enum):
    """Direction of access on a state variable."""

    READ = "read"
    WRITE = "write"
    READ_WRITE = "read_write"


class ProxyType(str, Enum):
    """Proxy pattern classification."""

    TRANSPARENT = "transparent"
    UUPS = "uups"
    BEACON = "beacon"
    DIAMOND = "diamond"
    MINIMAL = "minimal_eip1167"
    CUSTOM = "custom"
    NONE = "none"


# ---------------------------------------------------------------------------
# Supporting models
# ---------------------------------------------------------------------------


class AccessControl(BaseModel):
    """Access control information extracted from a function."""

    model_config = ConfigDict(populate_by_name=True)

    modifiers: list[str] = Field(default_factory=list)
    restricted_to: Optional[list[str]] = Field(None)
    only_owner: bool = Field(False, alias="onlyOwner")
    only_role: Optional[str] = Field(None, alias="onlyRole")
    requires_auth: bool = Field(False)


class Parameter(BaseModel):
    """A function parameter or return value."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    type_: str = Field(alias="type")
    indexed: bool = Field(False, description="Indexed in event definition")


class FunctionSignature(BaseModel):
    """Complete function signature."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    parameters: list[Parameter] = Field(default_factory=list)
    returns: list[Parameter] = Field(default_factory=list)
    selector: Optional[str] = Field(None, description="4-byte selector hex (e.g. 0xa9059cbb)")


class StorageSlotInfo(BaseModel):
    """Precise storage slot assignment for a state variable."""

    slot: int = Field(description="Storage slot number (0-indexed)")
    byte_offset: int = Field(0, description="Byte offset within the slot (0-31, right-aligned)")
    size_bytes: int = Field(description="Size of the variable in bytes")
    is_packed: bool = Field(False, description="Shares a slot with another variable")


# ---------------------------------------------------------------------------
# Core protocol graph nodes
# ---------------------------------------------------------------------------


class StateVariable(BaseModel):
    """A state variable declared in a contract."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    type_: str = Field(alias="type", description="Full Solidity type string")
    contract_id: Optional[str] = Field(None, description="Owning contract ID")
    visibility: Visibility
    is_constant: bool = Field(False, description="constant or immutable")
    is_indexed: bool = Field(False, description="Indexed in an event")
    initial_value: Optional[str] = Field(None)
    type_category: StateVariableType
    storage: Optional[StorageSlotInfo] = Field(None)
    line_start: int = Field(0)


class Parameter(BaseModel):  # noqa: F811 — redefine with full config
    """A function parameter or return value."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    type_: str = Field(alias="type")
    indexed: bool = Field(False)


class FunctionSignature(BaseModel):  # noqa: F811
    """Complete function signature."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    parameters: list[Parameter] = Field(default_factory=list)
    returns: list[Parameter] = Field(default_factory=list)
    selector: Optional[str] = Field(None)


class Function(BaseModel):
    """A function declared in a contract."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    contract_id: str
    visibility: Visibility
    signature: FunctionSignature
    is_pure: bool = False
    is_view: bool = False
    is_payable: bool = False
    is_constructor: bool = False
    is_fallback: bool = False
    is_receive: bool = False
    state_vars_read: list[str] = Field(default_factory=list)
    state_vars_written: list[str] = Field(default_factory=list)
    access_control: AccessControl = Field(default_factory=AccessControl)
    cyclomatic_complexity: int = Field(0)
    modifiers: list[str] = Field(default_factory=list)
    line_start: int = Field(0)
    line_end: int = Field(0)


class FunctionCall(BaseModel):
    """A call relationship from one function to another."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    caller_id: str
    callee_id: Optional[str] = Field(None, description="None for unresolved external targets")
    callee_name: str
    callee_contract: Optional[str] = Field(None)
    call_type: CallType
    is_delegatecall: bool = False
    value_transfer: bool = Field(False, description="Transfers ETH with the call")
    line_number: int = Field(0)
    arguments: list[str] = Field(default_factory=list)


class Event(BaseModel):
    """An event declaration in a contract."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    contract_id: str
    parameters: list[Parameter] = Field(default_factory=list)
    line_start: int = Field(0)


class Contract(BaseModel):
    """A smart contract (Solidity or Vyper)."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    language: ContractLanguage = ContractLanguage.SOLIDITY
    compiler_version: Optional[str] = Field(None)
    file_path: str
    hex_size: Optional[int] = Field(None, description="Bytecode size in bytes")
    is_library: bool = False
    is_abstract: bool = False
    is_interface: bool = False
    parent_contracts: list[str] = Field(default_factory=list, description="Direct inheritance list")
    full_inheritance: list[str] = Field(
        default_factory=list, description="Full flattened inheritance chain"
    )
    source_hash: Optional[str] = Field(None)
    proxy_type: ProxyType = Field(ProxyType.NONE)


class ExternalDependency(BaseModel):
    """An external contract or protocol dependency referenced in the codebase."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    interface: Optional[str] = Field(None, description="Known interface: ERC20, ERC721, etc.")
    address: Optional[str] = Field(None, description="Hardcoded address, if any")
    references: list[str] = Field(default_factory=list, description="Function IDs that call it")
    call_sites: list[str] = Field(default_factory=list, description="Caller function names")


class AssetFlow(BaseModel):
    """An asset transfer relationship between two functions."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    from_function_id: str
    to_function_id: Optional[str] = None
    asset_type: str = Field(description="ETH | ERC20 | ERC721 | UNKNOWN")
    token_address: Optional[str] = Field(None)
    amount: Optional[str] = Field(None, description="Amount expression if statically determinable")
    is_conditional: bool = False
    line_number: int = Field(0)


class ProxyRelationship(BaseModel):
    """Describes a proxy→implementation relationship."""

    model_config = ConfigDict(populate_by_name=True)

    proxy_contract_id: str
    implementation_contract_id: Optional[str] = Field(
        None, description="Resolved implementation, if in-scope"
    )
    proxy_type: ProxyType
    implementation_slot: Optional[str] = Field(
        None, description="EIP-1967 storage slot hex, if applicable"
    )
    is_upgradeable: bool = False
    upgrade_function: Optional[str] = Field(None, description="Name of upgrade function")
    admin_function: Optional[str] = Field(None, description="Name of admin/owner function")


class VersionDiff(BaseModel):
    """Difference between two versions of a protocol."""

    model_config = ConfigDict(populate_by_name=True)

    added_contracts: list[str] = Field(default_factory=list)
    removed_contracts: list[str] = Field(default_factory=list)
    added_functions: list[str] = Field(default_factory=list)
    removed_functions: list[str] = Field(default_factory=list)
    modified_functions: list[str] = Field(default_factory=list)
    added_state_vars: list[str] = Field(default_factory=list)
    removed_state_vars: list[str] = Field(default_factory=list)
    new_external_deps: list[str] = Field(default_factory=list)
    attack_surface_delta: str = Field(
        "unknown", description="low | medium | high | critical"
    )


# ---------------------------------------------------------------------------
# Root graph output
# ---------------------------------------------------------------------------


class ProtocolGraph(BaseModel):
    """
    Complete protocol graph extracted from a set of contracts.

    This is the primary output of Phase 1.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        json_encoders={
            Visibility: lambda v: v.value,
            StateVariableType: lambda v: v.value,
            AccessType: lambda v: v.value,
            CallType: lambda v: v.value,
            ProxyType: lambda v: v.value,
            ContractLanguage: lambda v: v.value,
        },
    )

    # Primary nodes
    contracts: list[Contract] = Field(default_factory=list)
    functions: list[Function] = Field(default_factory=list)
    state_variables: list[StateVariable] = Field(default_factory=list)
    events: list[Event] = Field(default_factory=list)

    # Primary edges
    function_calls: list[FunctionCall] = Field(default_factory=list)
    asset_flows: list[AssetFlow] = Field(default_factory=list)

    # Dependency and proxy topology
    external_dependencies: list[ExternalDependency] = Field(default_factory=list)
    proxy_relationships: list[ProxyRelationship] = Field(default_factory=list)

    # Optional diff (populated only in version-diff mode)
    version_diff: Optional[VersionDiff] = Field(None)

    # Source metadata
    source_available: bool = Field(True)
    analysis_metadata: dict[str, Any] = Field(default_factory=dict)
