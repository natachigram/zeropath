"""
Tests for zeropath.asset_flow

Uses only model objects (no Slither) to test the structural heuristic
path. IR-based tests require a live Slither environment and are tested
via integration tests.
"""

import pytest

from zeropath.asset_flow import AssetFlowTracker
from zeropath.models import CallType, Function, FunctionCall, FunctionSignature, Visibility


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_function(name: str, is_payable: bool = False, contract_id: str = "c1") -> Function:
    return Function(
        name=name,
        contract_id=contract_id,
        visibility=Visibility.EXTERNAL,
        signature=FunctionSignature(name=name),
        is_payable=is_payable,
        line_start=0,
        line_end=0,
    )


def _make_call(
    caller_id: str,
    callee_id: str | None,
    callee_name: str,
    call_type: CallType = CallType.EXTERNAL,
    value_transfer: bool = False,
) -> FunctionCall:
    return FunctionCall(
        caller_id=caller_id,
        callee_id=callee_id,
        callee_name=callee_name,
        call_type=call_type,
        value_transfer=value_transfer,
        line_number=10,
    )


# ---------------------------------------------------------------------------
# extract_from_models: ETH flows
# ---------------------------------------------------------------------------


class TestEthFlows:
    def test_no_flows_for_empty_inputs(self):
        flows = AssetFlowTracker.extract_from_models([], [])
        assert flows == []

    def test_no_flow_from_non_payable(self):
        """An external call from a non-payable function should NOT create an ETH flow."""
        f = _make_function("transfer", is_payable=False)
        call = _make_call(f.id, "callee-id", "someFunc", CallType.EXTERNAL, value_transfer=True)
        flows = AssetFlowTracker.extract_from_models([f], [call])
        eth_flows = [fl for fl in flows if fl.asset_type == "ETH"]
        assert len(eth_flows) == 0

    def test_eth_flow_from_payable_with_value(self):
        """External call with value_transfer from a payable function → ETH flow."""
        caller = _make_function("deposit", is_payable=True)
        callee_id = "callee-uuid"
        call = _make_call(caller.id, callee_id, "forward", CallType.EXTERNAL, value_transfer=True)
        flows = AssetFlowTracker.extract_from_models([caller], [call])
        eth_flows = [fl for fl in flows if fl.asset_type == "ETH"]
        assert len(eth_flows) == 1
        assert eth_flows[0].from_function_id == caller.id

    def test_no_eth_flow_for_internal_calls(self):
        """Internal calls from payable functions should NOT produce ETH flows."""
        caller = _make_function("deposit", is_payable=True)
        call = _make_call(caller.id, "other-id", "_processDeposit", CallType.INTERNAL)
        flows = AssetFlowTracker.extract_from_models([caller], [call])
        eth_flows = [fl for fl in flows if fl.asset_type == "ETH"]
        assert len(eth_flows) == 0


# ---------------------------------------------------------------------------
# extract_from_models: Token flows
# ---------------------------------------------------------------------------


class TestTokenFlows:
    def test_erc20_transfer_detected(self):
        caller = _make_function("sendTokens")
        call = _make_call(caller.id, None, "transfer", CallType.EXTERNAL)
        flows = AssetFlowTracker.extract_from_models([caller], [call])
        token_flows = [fl for fl in flows if fl.asset_type == "ERC20"]
        assert len(token_flows) == 1

    def test_transferFrom_detected(self):
        caller = _make_function("pullTokens")
        call = _make_call(caller.id, "token-fn-id", "transferFrom", CallType.EXTERNAL)
        flows = AssetFlowTracker.extract_from_models([caller], [call])
        assert any(fl.asset_type == "ERC20" for fl in flows)

    def test_safeTransfer_detected(self):
        caller = _make_function("distribute")
        call = _make_call(caller.id, None, "safeTransfer", CallType.EXTERNAL)
        flows = AssetFlowTracker.extract_from_models([caller], [call])
        assert any(fl.asset_type == "ERC20" for fl in flows)

    def test_internal_transfer_not_flagged(self):
        """An INTERNAL call to 'transfer' (common helper name) should not be flagged."""
        caller = _make_function("_doTransfer")
        call = _make_call(caller.id, "helper-id", "transfer", CallType.INTERNAL)
        flows = AssetFlowTracker.extract_from_models([caller], [call])
        # Internal call — should not produce ERC20 flow
        assert len(flows) == 0

    def test_no_duplicate_flows(self):
        """Same (caller, callee, asset_type) pair should appear only once."""
        caller = _make_function("batch")
        callee_id = "token-id"
        calls = [
            _make_call(caller.id, callee_id, "transfer", CallType.EXTERNAL)
            for _ in range(5)
        ]
        flows = AssetFlowTracker.extract_from_models([caller], calls)
        erc20_flows = [fl for fl in flows if fl.asset_type == "ERC20"]
        assert len(erc20_flows) == 1


# ---------------------------------------------------------------------------
# analyze_value_flow_paths
# ---------------------------------------------------------------------------


class TestValueFlowPaths:
    def test_single_node_no_flows(self):
        paths = AssetFlowTracker.analyze_value_flow_paths("fn-a", [])
        assert paths == [["fn-a"]]

    def test_linear_chain(self):
        from zeropath.models import AssetFlow

        flows = [
            AssetFlow(from_function_id="a", to_function_id="b", asset_type="ETH", line_number=0),
            AssetFlow(from_function_id="b", to_function_id="c", asset_type="ETH", line_number=0),
        ]
        paths = AssetFlowTracker.analyze_value_flow_paths("a", flows)
        assert len(paths) == 1
        assert paths[0] == ["a", "b", "c"]

    def test_cycle_does_not_hang(self):
        """Cycle detection prevents infinite loops."""
        from zeropath.models import AssetFlow

        flows = [
            AssetFlow(from_function_id="a", to_function_id="b", asset_type="ETH", line_number=0),
            AssetFlow(from_function_id="b", to_function_id="a", asset_type="ETH", line_number=0),
        ]
        # Should return without hanging
        paths = AssetFlowTracker.analyze_value_flow_paths("a", flows)
        assert isinstance(paths, list)

    def test_branching_paths(self):
        from zeropath.models import AssetFlow

        flows = [
            AssetFlow(from_function_id="root", to_function_id="branch1", asset_type="ETH", line_number=0),
            AssetFlow(from_function_id="root", to_function_id="branch2", asset_type="ETH", line_number=0),
        ]
        paths = AssetFlowTracker.analyze_value_flow_paths("root", flows)
        assert len(paths) == 2
        all_nodes = {node for path in paths for node in path}
        assert "branch1" in all_nodes
        assert "branch2" in all_nodes
