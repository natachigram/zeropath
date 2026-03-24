"""
Core data models for the protocol graph.

These models define the fundamental structures extracted from smart contracts.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class Visibility(str, Enum):
    """Function/variable visibility levels."""
    PUBLIC = "public"
    PRIVATE = "private"
    INTERNAL = "internal"
    EXTERNAL = "external"


class StateVariableType(str, Enum):
    """State variable type classification."""
    PRIMITIVE = "primitive"
    MAPPING = "mapping"
    ARRAY = "array"
    STRUCT = "struct"
    ADDRESS = "address"
    BYTES = "bytes"
    STRING = "string"
    ENUM = "enum"


class AccessType(str, Enum):
    """Type of access on a variable."""
    READ = "read"
    WRITE = "write"
    READ_WRITE = "read_write"


class CallType(str, Enum):
    """Type of function call."""
    INTERNAL = "internal"
    EXTERNAL = "external"
    DELEGATECALL = "delegatecall"
    STATICCALL = "staticcall"
    LOW_LEVEL = "low_level"
    LIBRARY = "library"


class AccessControl(BaseModel):
    """Access control information for a function."""
    modifiers: list[str] = Field(default_factory=list, description="Applied modifiers")
    restricted_to: Optional[list[str]] = Field(None, description="Restricted to addresses/roles")
    onlyOwner: bool = Field(False, description="Has onlyOwner modifier")
    onlyRole: Optional[str] = Field(None, description="Requires specific role")


class StateVariable(BaseModel):
    """State variable in a contract."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str = Field(description="Variable name")
    type_: str = Field(alias="type", description="Variable type (e.g., uint256, address)")
    visibility: Visibility = Field(description="State variable visibility")
    is_constant: bool = Field(False, description="Is immutable/constant")
    is_indexed: bool = Field(False, description="Is indexed (events only)")
    initial_value: Optional[str] = Field(None, description="Initial value if set")
    storage_slot: Optional[int] = Field(None, description="Storage slot number (extracted)")
    type_category: StateVariableType = Field(description="Variable type category")


class Parameter(BaseModel):
    """Function parameter."""
    name: str
    type_: str = Field(alias="type")
    indexed: bool = Field(False, description="Indexed in events")


class FunctionSignature(BaseModel):
    """Function signature information."""
    name: str
    parameters: list[Parameter] = Field(default_factory=list)
    returns: list[Parameter] = Field(default_factory=list)
    selector: Optional[str] = Field(None, description="4-byte function selector")


class Function(BaseModel):
    """Represents a function in a contract."""
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
    state_vars_read: list[str] = Field(default_factory=list, description="State vars read")
    state_vars_written: list[str] = Field(default_factory=list, description="State vars written")
    access_control: AccessControl = Field(default_factory=AccessControl)
    cyclomatic_complexity: int = Field(0, description="Estimated complexity")
    line_start: int
    line_end: int


class FunctionCall(BaseModel):
    """Represents a call from one function to another."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    caller_id: str = Field(description="ID of calling function")
    callee_id: Optional[str] = Field(None, description="ID of called function (if internal)")
    callee_name: str = Field(description="Name of called function")
    callee_contract: Optional[str] = Field(None, description="Target contract name")
    call_type: CallType
    is_delegatecall: bool = False
    value_transfer: bool = Field(False, description="Transfers ETH/tokens")
    line_number: int
    arguments: list[str] = Field(default_factory=list, description="Argument values/references")


class Contract(BaseModel):
    """Represents a smart contract."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    language: str = "solidity"
    version: Optional[str] = Field(None, description="Solidity version")
    file_path: str
    hex_size: Optional[int] = Field(None, description="Bytecode size in bytes")
    is_library: bool = False
    is_abstract: bool = False
    parent_contracts: list[str] = Field(default_factory=list, description="Inherited contracts")
    source_hash: Optional[str] = Field(None, description="Source code hash")


class ExternalDependency(BaseModel):
    """External contract or interface dependency."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    interface: Optional[str] = Field(None, description="Known interface (ERC20, etc.)")
    address: Optional[str] = Field(None, description="Known address if hardcoded")
    references: list[str] = Field(default_factory=list, description="Functions that use it")


class AssetFlow(BaseModel):
    """Tracks asset flow through functions."""
    from_function_id: str
    to_function_id: Optional[str]
    asset_type: str = Field(description="ETH, token address, etc.")
    amount: Optional[str] = Field(None, description="Amount if traceable")
    is_conditional: bool = False
    line_number: int


class ProtocolGraph(BaseModel):
    """Complete protocol graph extracted from contracts."""
    model_config = ConfigDict(
        json_encoders={
            Visibility: lambda v: v.value,
            StateVariableType: lambda v: v.value,
            AccessType: lambda v: v.value,
            CallType: lambda v: v.value,
        }
    )

    contracts: list[Contract] = Field(default_factory=list)
    functions: list[Function] = Field(default_factory=list)
    state_variables: list[StateVariable] = Field(default_factory=list)
    function_calls: list[FunctionCall] = Field(default_factory=list)
    external_dependencies: list[ExternalDependency] = Field(default_factory=list)
    asset_flows: list[AssetFlow] = Field(default_factory=list)
    analysis_metadata: dict[str, Any] = Field(default_factory=dict, description="Metadata about analysis")
