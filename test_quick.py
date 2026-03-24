#!/usr/bin/env python3
"""Direct test of models module."""

import sys
import importlib.util

spec = importlib.util.spec_from_file_location("models", "src/zeropath/models.py")
models = importlib.util.module_from_spec(spec)
spec.loader.exec_module(models)

# Test creating models
contract = models.Contract(name="Token", file_path="Token.sol")
print(f"✓ Contract: {contract.name}")

sig = models.FunctionSignature(name="transfer")
func = models.Function(
    name="transfer",
    contract_id=contract.id,
    visibility=models.Visibility.EXTERNAL,
    signature=sig,
    line_start=50,
    line_end=60
)
print(f"✓ Function: {func.name}")

var = models.StateVariable(
    name="balances",
    type="mapping(address => uint256)",
    visibility=models.Visibility.PRIVATE,
    type_category=models.StateVariableType.MAPPING
)
print(f"✓ State Variable: {var.name}")

call = models.FunctionCall(
    caller_id=func.id,
    callee_name="_update",
    call_type=models.CallType.INTERNAL,
    line_number=55
)
print(f"✓ Function Call: {call.callee_name}")

graph = models.ProtocolGraph(
    contracts=[contract],
    functions=[func],
    state_variables=[var],
    function_calls=[call]
)

print(f"\n✓ Protocol Graph:")
print(f"  - {len(graph.contracts)} Contract(s)")
print(f"  - {len(graph.functions)} Function(s)")
print(f"  - {len(graph.state_variables)} State Variable(s)")
print(f"  - {len(graph.function_calls)} Function Call(s)")

print("\n✅ All tests passed!")
