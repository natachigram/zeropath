"""
Unit tests for zeropath.parser

Tests cover the pure utility functions and type-categorization helpers
without requiring a live Slither / solc installation. Live parsing is
covered by test_integration.py.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from zeropath.exceptions import ParsingError
from zeropath.models import ContractLanguage, StateVariableType, Visibility
from zeropath.parser import (
    ContractParser,
    _categorize_type,
    _extract_external_func_name,
    _guess_interface,
    _parse_visibility,
    detect_language,
    extract_compiler_version,
)


# ---------------------------------------------------------------------------
# detect_language
# ---------------------------------------------------------------------------


class TestDetectLanguage:
    def test_sol_extension(self, tmp_path: Path):
        f = tmp_path / "Token.sol"
        f.write_text("pragma solidity ^0.8.0;")
        assert detect_language(f) == ContractLanguage.SOLIDITY

    def test_vy_extension(self, tmp_path: Path):
        f = tmp_path / "Token.vy"
        f.write_text("# @version 0.3.10")
        assert detect_language(f) == ContractLanguage.VYPER

    def test_pragma_solidity_detection(self, tmp_path: Path):
        f = tmp_path / "Token.txt"
        f.write_text("pragma solidity ^0.8.0;")
        assert detect_language(f) == ContractLanguage.SOLIDITY

    def test_vyper_version_comment(self, tmp_path: Path):
        f = tmp_path / "Token.txt"
        f.write_text("# @version 0.3.10\n@external\ndef foo(): pass")
        assert detect_language(f) == ContractLanguage.VYPER

    def test_unknown_extension(self, tmp_path: Path):
        f = tmp_path / "Mystery.xyz"
        f.write_text("nothing recognisable")
        assert detect_language(f) == ContractLanguage.UNKNOWN


# ---------------------------------------------------------------------------
# extract_compiler_version
# ---------------------------------------------------------------------------


class TestExtractCompilerVersion:
    def test_solidity_caret_version(self, tmp_path: Path):
        f = tmp_path / "Token.sol"
        f.write_text("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;")
        assert extract_compiler_version(f) == "^0.8.20"

    def test_solidity_range_version(self, tmp_path: Path):
        f = tmp_path / "Token.sol"
        f.write_text("pragma solidity >=0.8.0 <0.9.0;")
        assert extract_compiler_version(f) == ">=0.8.0 <0.9.0"

    def test_vyper_version(self, tmp_path: Path):
        f = tmp_path / "Token.vy"
        f.write_text("# @version 0.3.10\n")
        assert extract_compiler_version(f) == "0.3.10"

    def test_no_pragma(self, tmp_path: Path):
        f = tmp_path / "Foo.sol"
        f.write_text("contract Foo {}")
        assert extract_compiler_version(f) is None


# ---------------------------------------------------------------------------
# _parse_visibility
# ---------------------------------------------------------------------------


class TestParseVisibility:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("public", Visibility.PUBLIC),
            ("Public", Visibility.PUBLIC),
            ("external", Visibility.EXTERNAL),
            ("private", Visibility.PRIVATE),
            ("internal", Visibility.INTERNAL),
            ("default", Visibility.INTERNAL),
            ("", Visibility.INTERNAL),
        ],
    )
    def test_mapping(self, raw: str, expected: Visibility):
        assert _parse_visibility(raw) == expected


# ---------------------------------------------------------------------------
# _categorize_type
# ---------------------------------------------------------------------------


class TestCategorizeType:
    @pytest.mark.parametrize(
        "type_str, expected",
        [
            ("uint256", StateVariableType.PRIMITIVE),
            ("int128", StateVariableType.PRIMITIVE),
            ("bool", StateVariableType.PRIMITIVE),
            ("address", StateVariableType.ADDRESS),
            ("address payable", StateVariableType.ADDRESS),
            ("mapping(address => uint256)", StateVariableType.MAPPING),
            ("uint256[]", StateVariableType.ARRAY),
            ("uint256[10]", StateVariableType.ARRAY),
            ("bytes32", StateVariableType.BYTES),
            ("bytes", StateVariableType.BYTES),
            ("string", StateVariableType.STRING),
            ("struct Position", StateVariableType.STRUCT),
            ("enum Status", StateVariableType.ENUM),
        ],
    )
    def test_categorization(self, type_str: str, expected: StateVariableType):
        assert _categorize_type(type_str) == expected


# ---------------------------------------------------------------------------
# _extract_external_func_name
# ---------------------------------------------------------------------------


class TestExtractExternalFuncName:
    def test_member_name_attribute(self):
        # Use a plain object to avoid MagicMock's built-in .called bool property
        class _Called:
            member_name = "transfer"

        class _Call:
            called = _Called()

        assert _extract_external_func_name(_Call()) == "transfer"

    def test_fallback_string_parse(self):
        # Object without .called → falls through to string-parsing heuristic
        class _Call:
            def __str__(self) -> str:
                return "token.transfer(to, amount)"

        result = _extract_external_func_name(_Call())
        assert result == "transfer"

    def test_returns_none_on_no_match(self):
        class _Call:
            def __str__(self) -> str:
                return "nofunction"

        result = _extract_external_func_name(_Call())
        assert result is None


# ---------------------------------------------------------------------------
# _guess_interface
# ---------------------------------------------------------------------------


class TestGuessInterface:
    def test_known_interfaces(self):
        assert _guess_interface("IERC20") == "ERC20"
        assert _guess_interface("IERC721") == "ERC721"
        assert _guess_interface("AggregatorV3Interface") == "Chainlink"
        assert _guess_interface("ILendingPool") == "Aave"

    def test_unknown_returns_none(self):
        assert _guess_interface("MyCustomContract") is None


# ---------------------------------------------------------------------------
# ContractParser initialisation
# ---------------------------------------------------------------------------


class TestContractParserInit:
    def test_defaults(self):
        parser = ContractParser()
        assert parser.solc_version is None
        assert parser.extract_storage is True
        assert parser.detect_proxies is True

    def test_custom_solc(self):
        parser = ContractParser(solc_version="0.8.19")
        assert parser.solc_version == "0.8.19"

    def test_nonexistent_file_raises(self):
        parser = ContractParser()
        with pytest.raises(ParsingError, match="not found"):
            parser.parse_contract(Path("/does/not/exist.sol"))
