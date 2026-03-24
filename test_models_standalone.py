#!/usr/bin/env python3
"""
Quick test of zeropath models without Slither dependency.
"""

import sys
sys.path.insert(0, '/Users/macbook/Documents/zeropath/src')

# Import directly from modules, not from package
from zeropath.models import (
    Contract, Function, StateVariable, FunctionCall, 
    FunctionSignature, Parameter, Visibility, StateVariableType, CallType, ProtocolGraph
)
import json

# Create example contracts and functions
contract = Contract(name="Token", file_path="contracts/Token.sol")
print(f"✓ Created contract: {contract.name}")

sig = FunctionSignature(
    name="transfer",
    parameters=[
        Parameter(name="to", type="address"),
        Parameter(name="amount", type="uint256")
    ],
    returns=[Parameter(name="success", type="bool")]
)
print(f"✓ Created function signature: {sig.name}")

func = Function(
    name="transfer",
    contract_id=contract.id,
    visibility=Visibility.EXTERNAL,
    signature=sig,
    is_payable=False,
    line_start=50,
    line_end=60,
    state_vars_read=["balances"],
    state_vars_written=["balances"]
)
print(f"✓ Created function: {func.name} ({func.visibility.value})")

var = StateVariable(
    name="balances",
    type="mapping(address => uint256)",
    visibility=Visibility.PRIVATE,
    type_category=StateVariableType.MAPPING
)
print(f"✓ Created state variable: {var.name} ({var.type_category.value})")

call = FunctionCall(
    caller_id=func.id,
    callee_name="_update",
    callee_contract="Token",
    call_type=CallType.INTERNAL,
    line_number=55
)
print(f"✓ Created function call: {call.caller_id} → {call.callee_name}")

# Build protocol graph
graph = ProtocolGraph(
    contracts=[contract],
    functions=[func],
    state_variables=[var],
    function_calls=[call]
)

print(f"\n✓ Created protocol graph:")
print(f"  Contracts: {len(graph.contracts)}")
print(f"  Functions: {len(graph.functions)}")
print(f"  State variables: {len(graph.state_variables)}")
print(f"  Function calls: {len(graph.function_calls)}")

# Test JSON serialization
graph_json = graph.model_dump(mode='json')
print(f"\n✓ Serialized to JSON: {len(json.dumps(graph_json))} bytes")

# Show sample output
print(f"\n✓ Sample function data:")
func_data = graph.functions[0].model_dump(mode='json')
print(json.dumps({
    "name": func_data["name"],
    "visibility": func_data["visibility"],
    "is_payable": func_data["is_payable"],
    "parameters": [p["name"] for p in func_data["signature"]["parameters"]]
}, indent=2))

print("\n✅ ALL TESTS PASSED!")
