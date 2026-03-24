"""
Unit tests for storage analyzer module.
"""

from unittest.mock import MagicMock

import pytest

from zeropath.storage_analyzer import StorageAnalyzer


@pytest.fixture
def mock_contract():
    """Create a mock contract."""
    return MagicMock()


@pytest.fixture
def mock_var_uint256():
    """Create a mock uint256 variable."""
    var = MagicMock()
    var.name = "balance"
    var.type = "uint256"
    return var


@pytest.fixture
def mock_var_address():
    """Create a mock address variable."""
    var = MagicMock()
    var.name = "owner"
    var.type = "address"
    return var


class TestStorageAnalyzer:
    """Tests for StorageAnalyzer."""

    def test_estimate_variable_size_uint256(self):
        """Test estimating size of uint256."""
        var = MagicMock()
        var.type = "uint256"

        size = StorageAnalyzer._estimate_variable_size(var)
        assert size == 1

    def test_estimate_variable_size_address(self):
        """Test estimating size of address."""
        var = MagicMock()
        var.type = "address"

        size = StorageAnalyzer._estimate_variable_size(var)
        assert size == 1

    def test_estimate_variable_size_bool(self):
        """Test estimating size of bool."""
        var = MagicMock()
        var.type = "bool"

        size = StorageAnalyzer._estimate_variable_size(var)
        assert size == 1

    def test_estimate_variable_size_uint128(self):
        """Test estimating size of uint128."""
        var = MagicMock()
        var.type = "uint128"

        size = StorageAnalyzer._estimate_variable_size(var)
        assert size == 1

    def test_estimate_variable_size_mapping(self):
        """Test estimating size of mapping."""
        var = MagicMock()
        var.type = "mapping(address => uint256)"

        size = StorageAnalyzer._estimate_variable_size(var)
        assert size == 1

    def test_estimate_variable_size_array(self):
        """Test estimating size of dynamic array."""
        var = MagicMock()
        var.type = "uint256[]"

        size = StorageAnalyzer._estimate_variable_size(var)
        assert size == 1

    def test_extract_storage_layout_empty_contract(self, mock_contract):
        """Test extracting layout from contract with no state vars."""
        mock_contract.state_variables = []

        layout = StorageAnalyzer.extract_storage_layout(mock_contract)
        assert len(layout) == 0

    def test_analyze_packing_empty_contract(self, mock_contract):
        """Test analyzing packing of empty contract."""
        mock_contract.state_variables = []

        packing = StorageAnalyzer.analyze_packing(mock_contract)
        assert packing["total_slots"] == 1
        assert packing["wasted_bytes"] == 32

    def test_analyze_packing_single_variable(self, mock_contract, mock_var_uint256):
        """Test packing analysis with single variable."""
        mock_contract.state_variables = [mock_var_uint256]

        packing = StorageAnalyzer.analyze_packing(mock_contract)
        assert packing["total_slots"] == 1
        assert packing["packed_variables"][0]["name"] == "balance"

    def test_analyze_packing_multiple_variables(
        self, mock_contract, mock_var_uint256, mock_var_address
    ):
        """Test packing with multiple variables."""
        mock_contract.state_variables = [mock_var_uint256, mock_var_address]

        packing = StorageAnalyzer.analyze_packing(mock_contract)
        assert packing["total_slots"] >= 1
        assert len(packing["packed_variables"]) == 2
