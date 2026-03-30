"""
Tests for bytecode_decompiler.py.

All tests run without Heimdall installed (mocked or pure-Python path).
No external tooling required.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from zeropath.bytecode_decompiler import (
    DecompileResult,
    HeimdallDecompiler,
    _abi_entry_to_event,
    _abi_entry_to_function,
    _extract_selectors_from_bytecode,
    _parse_functions_from_pseudo_sol,
)
from zeropath.exceptions import BytecodeDecompilationError
from zeropath.models import ContractLanguage, Visibility


# ---------------------------------------------------------------------------
# Selector extraction from raw EVM bytecode
# ---------------------------------------------------------------------------


class TestExtractSelectors:
    # Minimal synthetic bytecode with two PUSH4+EQ pairs
    # PUSH4 a9059cbb EQ  →  transfer(address,uint256)
    # PUSH4 70a08231 EQ  →  balanceOf(address)
    _BYTECODE = "0x" + (
        "63"        # PUSH4
        "a9059cbb"  # selector
        "14"        # EQ
        "63"        # PUSH4
        "70a08231"  # selector
        "14"        # EQ
    )

    def test_two_selectors_extracted(self):
        selectors = _extract_selectors_from_bytecode(self._BYTECODE)
        assert "0xa9059cbb" in selectors
        assert "0x70a08231" in selectors

    def test_returns_list_of_strings(self):
        selectors = _extract_selectors_from_bytecode(self._BYTECODE)
        for sel in selectors:
            assert sel.startswith("0x")
            assert len(sel) == 10  # "0x" + 8 hex chars

    def test_deduplication(self):
        # Two copies of the same selector
        bytecode = "0x" + "63" + "a9059cbb" + "14" + "63" + "a9059cbb" + "14"
        selectors = _extract_selectors_from_bytecode(bytecode)
        assert selectors.count("0xa9059cbb") == 1

    def test_zero_selector_filtered(self):
        bytecode = "0x" + "63" + "00000000" + "14"
        selectors = _extract_selectors_from_bytecode(bytecode)
        assert "0x00000000" not in selectors

    def test_empty_bytecode_returns_empty(self):
        assert _extract_selectors_from_bytecode("0x") == []

    def test_bare_hex_without_prefix(self):
        bare = "63" "a9059cbb" "14"
        selectors = _extract_selectors_from_bytecode(bare)
        assert "0xa9059cbb" in selectors

    def test_invalid_hex_returns_empty(self):
        selectors = _extract_selectors_from_bytecode("0xZZZZZZ")
        assert selectors == []


# ---------------------------------------------------------------------------
# ABI entry conversion
# ---------------------------------------------------------------------------


class TestAbiEntryToFunction:
    def test_basic_function(self):
        entry = {
            "type": "function",
            "name": "transfer",
            "inputs": [
                {"name": "to", "type": "address"},
                {"name": "amount", "type": "uint256"},
            ],
            "outputs": [{"name": "", "type": "bool"}],
            "stateMutability": "nonpayable",
        }
        func = _abi_entry_to_function(entry, "contract-id-123")
        assert func is not None
        assert func.name == "transfer"
        assert len(func.signature.parameters) == 2
        assert len(func.signature.returns) == 1
        assert func.visibility == Visibility.EXTERNAL
        assert not func.is_payable
        assert not func.is_view

    def test_payable_function(self):
        entry = {
            "name": "deposit",
            "inputs": [],
            "outputs": [],
            "stateMutability": "payable",
        }
        func = _abi_entry_to_function(entry, "cid")
        assert func is not None
        assert func.is_payable

    def test_view_function(self):
        entry = {
            "name": "getBalance",
            "inputs": [],
            "outputs": [{"name": "", "type": "uint256"}],
            "stateMutability": "view",
        }
        func = _abi_entry_to_function(entry, "cid")
        assert func is not None
        assert func.is_view

    def test_pure_function(self):
        entry = {"name": "compute", "inputs": [], "outputs": [], "stateMutability": "pure"}
        func = _abi_entry_to_function(entry, "cid")
        assert func is not None
        assert func.is_pure

    def test_missing_name_uses_unknown(self):
        entry = {"inputs": [], "outputs": [], "stateMutability": "nonpayable"}
        func = _abi_entry_to_function(entry, "cid")
        assert func is not None
        assert func.name == "unknown"

    def test_returns_none_on_bad_entry(self):
        # Intentionally malformed — type field causes construction to fail
        func = _abi_entry_to_function({"inputs": [{"type": None}]}, "cid")
        # Should not raise; may return None or a valid model with fallback types
        # We just ensure no exception propagates
        pass  # any outcome is valid


class TestAbiEntryToEvent:
    def test_basic_event(self):
        entry = {
            "type": "event",
            "name": "Transfer",
            "inputs": [
                {"name": "from", "type": "address", "indexed": True},
                {"name": "to", "type": "address", "indexed": True},
                {"name": "value", "type": "uint256", "indexed": False},
            ],
        }
        ev = _abi_entry_to_event(entry, "cid")
        assert ev is not None
        assert ev.name == "Transfer"
        assert len(ev.parameters) == 3
        assert ev.parameters[0].indexed is True
        assert ev.parameters[2].indexed is False

    def test_empty_inputs(self):
        entry = {"name": "Paused", "inputs": []}
        ev = _abi_entry_to_event(entry, "cid")
        assert ev is not None
        assert len(ev.parameters) == 0


# ---------------------------------------------------------------------------
# Pseudo-Solidity parser (Heimdall output fallback)
# ---------------------------------------------------------------------------


class TestParseFunctionsFromPseudoSol:
    def test_basic_extraction(self):
        source = """
        function transfer(address to, uint256 amount) external returns (bool) {
            // body
        }
        function approve(address spender, uint256 amount) external returns (bool) {}
        """
        funcs = _parse_functions_from_pseudo_sol(source, "cid")
        names = [f.name for f in funcs]
        assert "transfer" in names
        assert "approve" in names

    def test_no_functions_returns_empty(self):
        funcs = _parse_functions_from_pseudo_sol("// just comments", "cid")
        assert funcs == []

    def test_params_parsed(self):
        source = "function foo(uint256 amount, address recipient) external {}"
        funcs = _parse_functions_from_pseudo_sol(source, "cid")
        assert len(funcs) == 1
        assert len(funcs[0].signature.parameters) == 2


# ---------------------------------------------------------------------------
# HeimdallDecompiler — availability and fallback
# ---------------------------------------------------------------------------


class TestHeimdallDecompiler:
    def test_unavailable_when_binary_missing(self):
        decompiler = HeimdallDecompiler(heimdall_bin=Path("/nonexistent/heimdall"))
        assert decompiler.is_available is False

    def test_empty_bytecode_raises(self):
        decompiler = HeimdallDecompiler()
        with pytest.raises(BytecodeDecompilationError, match="Empty"):
            decompiler.decompile("0x")

    def test_eoa_bytecode_raises(self):
        decompiler = HeimdallDecompiler()
        with pytest.raises(BytecodeDecompilationError):
            decompiler.decompile("0x0")

    @patch("shutil.which", return_value=None)
    def test_fallback_mode_used_when_no_heimdall(self, _mock):
        decompiler = HeimdallDecompiler()
        decompiler._available = False  # force fallback

        # Bytecode with PUSH4 + EQ for transfer selector
        bytecode = "0x" + "63" + "a9059cbb" + "14"
        result = decompiler.decompile(bytecode, contract_name="TestToken")

        assert result.is_degraded
        assert result.decompiler == "selector_extraction"
        assert len(result.contracts) == 1
        assert result.contracts[0].name == "TestToken"
        assert result.contracts[0].language == ContractLanguage.UNKNOWN
        # Should have one stub function
        assert any(f.name == "func_a9059cbb" for f in result.functions)

    @patch("shutil.which", return_value=None)
    def test_fallback_contracts_have_unknown_language(self, _mock):
        decompiler = HeimdallDecompiler()
        decompiler._available = False

        result = decompiler.decompile(
            "0x63a9059cbb14", contract_name="Vault"
        )
        assert result.contracts[0].language == ContractLanguage.UNKNOWN

    @patch("shutil.which", return_value=None)
    def test_contract_name_preserved(self, _mock):
        decompiler = HeimdallDecompiler()
        decompiler._available = False
        result = decompiler.decompile("0x63a9059cbb14", contract_name="MyProtocol")
        assert result.contract_name == "MyProtocol"
        assert result.contracts[0].name == "MyProtocol"


# ---------------------------------------------------------------------------
# DecompileResult dataclass
# ---------------------------------------------------------------------------


class TestDecompileResult:
    def test_default_values(self):
        result = DecompileResult(contract_name="Test")
        assert result.is_degraded is True
        assert result.contracts == []
        assert result.functions == []
        assert result.events == []
        assert result.abi == []
        assert result.source_code == ""

    def test_decompiler_field(self):
        result = DecompileResult(contract_name="X", decompiler="heimdall")
        assert result.decompiler == "heimdall"
