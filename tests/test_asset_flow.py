"""
Unit tests for asset flow tracker module.
"""

import pytest

from zeropath.asset_flow import AssetFlowTracker
from zeropath.models import (
    Function,
    FunctionCall,
    FunctionSignature,
    CallType,
    Visibility,
)


@pytest.fixture
def payable_function():
    """Create a payable function."""
    sig = FunctionSignature(name="deposit")
    return Function(
        name="deposit",
        contract_id="contract1",
        visibility=Visibility.PUBLIC,
        signature=sig,
        is_payable=True,
        line_start=1,
        line_end=10,
    )


@pytest.fixture
def non_payable_function():
    """Create a non-payable function."""
    sig = FunctionSignature(name="transfer")
    return Function(
        name="transfer",
        contract_id="contract1",
        visibility=Visibility.PUBLIC,
        signature=sig,
        is_payable=False,
        line_start=11,
        line_end=20,
    )


@pytest.fixture
def external_call():
    """Create an external function call."""
    return FunctionCall(
        caller_id="func1",
        callee_name="transfer",
        callee_contract="IERC20",
        call_type=CallType.EXTERNAL,
        line_number=15,
    )


@pytest.fixture
def internal_call():
    """Create an internal function call."""
    return FunctionCall(
        caller_id="func1",
        callee_id="func2",
        callee_name="helper",
        call_type=CallType.INTERNAL,
        line_number=20,
    )


class TestAssetFlowTracker:
    """Tests for AssetFlowTracker."""

    def test_extract_flows_empty(self):
        """Test extracting flows from empty protocol."""
        flows = AssetFlowTracker.extract_asset_flows([], [])
        assert len(flows) == 0

    def test_extract_flows_with_payable_function(
        self, payable_function, non_payable_function
    ):
        """Test extracting flows with payable function."""
        functions = [payable_function, non_payable_function]
        calls = []

        flows = AssetFlowTracker.extract_asset_flows(functions, calls)
        # Should extract flows but may be empty if no external calls
        assert isinstance(flows, list)

    def test_extract_flows_with_external_call(
        self, payable_function, external_call
    ):
        """Test extracting flows with external call."""
        functions = [payable_function]
        calls = [external_call]

        flows = AssetFlowTracker.extract_asset_flows(functions, calls)
        # Token transfer pattern should be detected
        assert len(flows) > 0

    def test_detect_token_transfers(self, external_call):
        """Test detecting token transfer patterns."""
        calls = [external_call]

        flows = AssetFlowTracker._detect_token_transfers([], calls)
        # transfer is a token function
        assert len(flows) > 0

    def test_detect_token_transfers_multiple(self):
        """Test detecting multiple token transfers."""
        calls = [
            FunctionCall(
                caller_id="func1",
                callee_name="transfer",
                call_type=CallType.EXTERNAL,
                line_number=10,
            ),
            FunctionCall(
                caller_id="func1",
                callee_name="approve",
                call_type=CallType.EXTERNAL,
                line_number=15,
            ),
        ]

        flows = AssetFlowTracker._detect_token_transfers([], calls)
        assert len(flows) == 2

    def test_analyze_value_flow_paths_single_func(self, payable_function):
        """Test analyzing value flow paths."""
        functions = [payable_function]
        calls = []

        paths = AssetFlowTracker.analyze_value_flow_paths(
            payable_function.id, functions, calls
        )
        # Should return at least one path
        assert len(paths) > 0

    def test_analyze_value_flow_paths_with_calls(
        self, payable_function, non_payable_function
    ):
        """Test analyzing paths with function calls."""
        functions = [payable_function, non_payable_function]
        calls = [
            FunctionCall(
                caller_id=payable_function.id,
                callee_id=non_payable_function.id,
                callee_name="transfer",
                call_type=CallType.INTERNAL,
                line_number=5,
            ),
        ]

        paths = AssetFlowTracker.analyze_value_flow_paths(
            payable_function.id, functions, calls
        )
        # Should find path from deposit to transfer
        assert len(paths) > 0
