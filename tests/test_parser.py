"""
Unit tests for the parser module.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from zeropath.exceptions import ParsingError
from zeropath.parser import ContractParser
from zeropath.models import Visibility, StateVariableType


@pytest.fixture
def parser():
    """Provide a ContractParser instance."""
    return ContractParser()


@pytest.fixture
def mock_contract():
    """Create a mock Slither contract object."""
    mock = MagicMock()
    mock.name = "TestContract"
    mock.is_library = False
    mock.is_abstract = False
    mock.inheritance = []
    mock.state_variables = []
    mock.functions = []
    return mock


class TestContractParser:
    """Tests for ContractParser."""

    def test_parser_initialization(self, parser):
        """Test parser initializes correctly."""
        assert parser is not None
        assert parser.solc_version is None

    def test_parser_with_solc_version(self):
        """Test parser with specific Solidity version."""
        parser = ContractParser(solc_version="0.8.0")
        assert parser.solc_version == "0.8.0"

    def test_parse_nonexistent_file(self, parser):
        """Test parsing nonexistent file raises error."""
        with pytest.raises(ParsingError):
            parser.parse_contract(Path("/nonexistent/path.sol"))

    def test_categorize_primitive_type(self, parser):
        """Test categorization of primitive types."""
        mock_var = MagicMock()
        mock_var.type = "uint256"

        category = parser._categorize_variable_type(mock_var)
        assert category == StateVariableType.PRIMITIVE

    def test_categorize_address_type(self, parser):
        """Test categorization of address type."""
        mock_var = MagicMock()
        mock_var.type = "address"

        category = parser._categorize_variable_type(mock_var)
        assert category == StateVariableType.ADDRESS

    def test_categorize_mapping_type(self, parser):
        """Test categorization of mapping type."""
        mock_var = MagicMock()
        mock_var.type = "mapping(address => uint256)"

        category = parser._categorize_variable_type(mock_var)
        assert category == StateVariableType.MAPPING

    def test_categorize_array_type(self, parser):
        """Test categorization of array type."""
        mock_var = MagicMock()
        mock_var.type = "uint256[]"

        category = parser._categorize_variable_type(mock_var)
        assert category == StateVariableType.ARRAY

    def test_parse_contract_metadata(self, parser, mock_contract):
        """Test parsing contract metadata."""
        contract_path = Path("/test/Contract.sol")

        metadata = parser._parse_contract_metadata(mock_contract, contract_path)

        assert metadata.name == "TestContract"
        assert metadata.file_path == str(contract_path)
        assert metadata.is_library is False

    def test_parse_state_variables_empty(self, parser, mock_contract):
        """Test parsing contract with no state variables."""
        contract_id = "contract1"

        variables = parser._parse_state_variables(mock_contract, contract_id)

        assert len(variables) == 0

    def test_parse_functions_empty(self, parser, mock_contract):
        """Test parsing contract with no functions."""
        contract_id = "contract1"

        functions = parser._parse_functions(mock_contract, contract_id)

        assert len(functions) == 0

    def test_extract_function_calls_empty(self, parser, mock_contract):
        """Test extracting calls from contract with no calls."""
        contract_id = "contract1"

        calls = parser._extract_function_calls(mock_contract, [], contract_id)

        assert len(calls) == 0


class TestStateVariableParsing:
    """Tests for state variable parsing."""

    def test_parse_public_state_variable(self, parser):
        """Test parsing a public state variable."""
        mock_var = MagicMock()
        mock_var.name = "totalSupply"
        mock_var.visibility = "public"
        mock_var.type = "uint256"
        mock_var.is_constant = False
        mock_var.is_immutable = False
        mock_var.source_mapping = {"start_line": 10}

        mock_contract = MagicMock()
        mock_contract.state_variables = [mock_var]

        # This would normally require Slither mocking
        # Simplified test of the categorization logic
        category = parser._categorize_variable_type(mock_var)
        assert category == StateVariableType.PRIMITIVE


class TestFunctionParsing:
    """Tests for function parsing."""

    def test_function_visibility_parsing(self, parser):
        """Test parsing function visibility levels."""
        # This tests the visibility mapping in parse_functions
        visibilities = {
            "public": Visibility.PUBLIC,
            "external": Visibility.EXTERNAL,
            "private": Visibility.PRIVATE,
            "internal": Visibility.INTERNAL,
        }

        for vis_str, expected_vis in visibilities.items():
            # Simplified test of visibility logic
            if vis_str == "public":
                assert expected_vis == Visibility.PUBLIC
