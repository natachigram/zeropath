"""
Unit tests for the models module.
"""

import pytest

from zeropath.models import (
    AccessControl,
    Contract,
    Function,
    FunctionCall,
    FunctionSignature,
    Parameter,
    StateVariable,
    Visibility,
    StateVariableType,
    CallType,
    AccessType,
)


class TestStateVariable:
    """Tests for StateVariable model."""

    def test_create_simple_state_variable(self):
        """Test creating a simple state variable."""
        var = StateVariable(
            name="balance",
            type="uint256",
            visibility=Visibility.PRIVATE,
            type_category=StateVariableType.PRIMITIVE,
        )
        assert var.name == "balance"
        assert var.type_ == "uint256"
        assert var.visibility == Visibility.PRIVATE
        assert var.is_constant is False

    def test_state_variable_with_defaults(self):
        """Test that state variable has proper defaults."""
        var = StateVariable(
            name="token",
            type="address",
            type_category=StateVariableType.ADDRESS,
        )
        assert var.initial_value is None
        assert var.storage_slot is None
        assert var.is_indexed is False

    def test_state_variable_mapping_type(self):
        """Test mapping type categorization."""
        var = StateVariable(
            name="balances",
            type="mapping(address => uint256)",
            type_category=StateVariableType.MAPPING,
        )
        assert var.type_category == StateVariableType.MAPPING


class TestParameter:
    """Tests for Parameter model."""

    def test_create_parameter(self):
        """Test creating a function parameter."""
        param = Parameter(name="recipient", type="address")
        assert param.name == "recipient"
        assert param.type_ == "address"
        assert param.indexed is False

    def test_parameter_indexed(self):
        """Test indexed parameter for events."""
        param = Parameter(name="from", type="address", indexed=True)
        assert param.indexed is True


class TestFunctionSignature:
    """Tests for FunctionSignature model."""

    def test_create_signature_no_params(self):
        """Test creating function signature with no parameters."""
        sig = FunctionSignature(name="initialize")
        assert sig.name == "initialize"
        assert len(sig.parameters) == 0
        assert len(sig.returns) == 0

    def test_create_signature_with_params(self):
        """Test creating signature with parameters and returns."""
        params = [Parameter(name="amount", type="uint256")]
        returns = [Parameter(name="success", type="bool")]
        sig = FunctionSignature(
            name="transfer",
            parameters=params,
            returns=returns,
        )
        assert len(sig.parameters) == 1
        assert len(sig.returns) == 1


class TestAccessControl:
    """Tests for AccessControl model."""

    def test_access_control_with_modifiers(self):
        """Test access control with modifiers."""
        ac = AccessControl(
            modifiers=["onlyOwner", "nonReentrant"],
            onlyOwner=True,
        )
        assert "onlyOwner" in ac.modifiers
        assert ac.onlyOwner is True

    def test_access_control_empty(self):
        """Test empty access control."""
        ac = AccessControl()
        assert len(ac.modifiers) == 0
        assert ac.onlyOwner is False


class TestFunction:
    """Tests for Function model."""

    def test_create_function(self):
        """Test creating a function model."""
        sig = FunctionSignature(name="transfer")
        func = Function(
            name="transfer",
            contract_id="contract1",
            visibility=Visibility.EXTERNAL,
            signature=sig,
            line_start=10,
            line_end=20,
        )
        assert func.name == "transfer"
        assert func.visibility == Visibility.EXTERNAL
        assert func.is_payable is False

    def test_payable_function(self):
        """Test identifying payable function."""
        sig = FunctionSignature(name="deposit")
        func = Function(
            name="deposit",
            contract_id="contract1",
            visibility=Visibility.PUBLIC,
            signature=sig,
            is_payable=True,
            line_start=1,
            line_end=5,
        )
        assert func.is_payable is True

    def test_function_state_var_access(self):
        """Test tracking state variable access."""
        sig = FunctionSignature(name="updateBalance")
        func = Function(
            name="updateBalance",
            contract_id="contract1",
            visibility=Visibility.INTERNAL,
            signature=sig,
            state_vars_read=["balance"],
            state_vars_written=["balance"],
            line_start=1,
            line_end=3,
        )
        assert "balance" in func.state_vars_read
        assert "balance" in func.state_vars_written


class TestFunctionCall:
    """Tests for FunctionCall model."""

    def test_internal_call(self):
        """Test internal function call."""
        call = FunctionCall(
            caller_id="func1",
            callee_id="func2",
            callee_name="helper",
            call_type=CallType.INTERNAL,
            line_number=15,
        )
        assert call.call_type == CallType.INTERNAL
        assert call.callee_id == "func2"

    def test_external_call(self):
        """Test external function call."""
        call = FunctionCall(
            caller_id="func1",
            callee_name="transfer",
            callee_contract="IERC20",
            call_type=CallType.EXTERNAL,
            line_number=20,
        )
        assert call.call_type == CallType.EXTERNAL
        assert call.callee_contract == "IERC20"

    def test_delegatecall(self):
        """Test delegatecall detection."""
        call = FunctionCall(
            caller_id="proxy",
            callee_name="implementation",
            call_type=CallType.DELEGATECALL,
            is_delegatecall=True,
            line_number=30,
        )
        assert call.is_delegatecall is True


class TestContract:
    """Tests for Contract model."""

    def test_create_contract(self):
        """Test creating contract model."""
        contract = Contract(
            name="Token",
            file_path="/path/to/Token.sol",
        )
        assert contract.name == "Token"
        assert contract.is_library is False

    def test_library_contract(self):
        """Test identifying library contract."""
        contract = Contract(
            name="SafeMath",
            file_path="/path/to/SafeMath.sol",
            is_library=True,
        )
        assert contract.is_library is True

    def test_contract_inheritance(self):
        """Test contract inheritance tracking."""
        contract = Contract(
            name="ERC20Extended",
            file_path="/path/to/ERC20Extended.sol",
            parent_contracts=["ERC20"],
        )
        assert "ERC20" in contract.parent_contracts
