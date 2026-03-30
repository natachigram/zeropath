"""
Tests for onchain_fetcher.py.

All HTTP calls are mocked — no real network access needed.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from zeropath.exceptions import ZeropathError
from zeropath.onchain_fetcher import (
    CHAIN_IDS,
    OnChainFetcher,
    OnChainSource,
    _chain_name,
    _normalise_address,
    _parse_etherscan_source,
    _resolve_chain,
)


# ---------------------------------------------------------------------------
# Address normalisation
# ---------------------------------------------------------------------------


class TestNormaliseAddress:
    def test_valid_address_lowercased(self):
        addr = _normalise_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
        assert addr == "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"

    def test_already_lowercase_unchanged(self):
        addr = _normalise_address("0xdeadbeef" + "0" * 32)
        assert addr.startswith("0x")

    def test_missing_0x_raises(self):
        with pytest.raises(ZeropathError, match="Invalid Ethereum address"):
            _normalise_address("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")

    def test_too_short_raises(self):
        with pytest.raises(ZeropathError, match="Invalid Ethereum address"):
            _normalise_address("0x1234")

    def test_too_long_raises(self):
        with pytest.raises(ZeropathError, match="Invalid Ethereum address"):
            _normalise_address("0x" + "a" * 41)


# ---------------------------------------------------------------------------
# Chain resolution
# ---------------------------------------------------------------------------


class TestResolveChain:
    def test_mainnet_by_name(self):
        assert _resolve_chain("mainnet") == 1

    def test_ethereum_alias(self):
        assert _resolve_chain("ethereum") == 1

    def test_polygon(self):
        assert _resolve_chain("polygon") == 137

    def test_numeric_string(self):
        assert _resolve_chain("42161") == 42161

    def test_case_insensitive(self):
        assert _resolve_chain("MAINNET") == 1

    def test_unknown_chain_raises(self):
        with pytest.raises(ZeropathError, match="Unknown chain"):
            _resolve_chain("notachain")

    def test_all_known_chains_resolve(self):
        for name, chain_id in CHAIN_IDS.items():
            assert _resolve_chain(name) == chain_id


class TestChainName:
    def test_mainnet(self):
        assert _chain_name(1) == "mainnet"

    def test_unknown_returns_str_id(self):
        assert _chain_name(9999999) == "9999999"


# ---------------------------------------------------------------------------
# Etherscan source parsing
# ---------------------------------------------------------------------------


class TestParseEtherscanSource:
    def test_single_file_source(self):
        sol = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
        result = _parse_etherscan_source(sol, "MyToken")
        assert "MyToken.sol" in result
        assert result["MyToken.sol"] == sol

    def test_double_brace_multi_file(self):
        sources = {
            "contracts/Token.sol": {"content": "contract Token {}"},
            "contracts/Vault.sol": {"content": "contract Vault {}"},
        }
        inner = json.dumps({"language": "Solidity", "sources": sources})
        # Etherscan wraps in an extra pair of braces
        wrapped = "{" + inner + "}"
        result = _parse_etherscan_source(wrapped, "Token")
        assert "Token.sol" in result
        assert "Vault.sol" in result
        assert result["Token.sol"] == "contract Token {}"

    def test_single_brace_json_with_sources(self):
        sources = {"Foo.sol": {"content": "contract Foo {}"}}
        json_str = json.dumps({"sources": sources})
        result = _parse_etherscan_source(json_str, "Foo")
        assert "Foo.sol" in result

    def test_empty_content_entries_skipped(self):
        sources = {
            "Good.sol": {"content": "contract Good {}"},
            "Empty.sol": {"content": ""},
        }
        inner = json.dumps({"sources": sources})
        wrapped = "{" + inner + "}"
        result = _parse_etherscan_source(wrapped, "Good")
        assert "Good.sol" in result
        assert "Empty.sol" not in result


# ---------------------------------------------------------------------------
# OnChainFetcher — mocked HTTP
# ---------------------------------------------------------------------------


def _make_etherscan_response(
    source_code: str = "contract Foo {}",
    contract_name: str = "Foo",
    compiler_version: str = "v0.8.19+commit.7dd6d404",
    abi: str = "[]",
) -> dict:
    return {
        "status": "1",
        "message": "OK",
        "result": [
            {
                "SourceCode": source_code,
                "ABI": abi,
                "ContractName": contract_name,
                "CompilerVersion": compiler_version,
                "OptimizationUsed": "1",
                "Runs": "200",
            }
        ],
    }


class TestOnChainFetcherEtherscan:
    def _make_fetcher(self) -> OnChainFetcher:
        return OnChainFetcher(etherscan_api_key="test-key", timeout=5)

    @patch("requests.Session.get")
    def test_single_file_source_returned(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_etherscan_response(
            source_code="pragma solidity ^0.8.0;\ncontract Foo {}"
        )
        mock_get.return_value = mock_resp

        fetcher = self._make_fetcher()
        result = fetcher.fetch("0x" + "a" * 40, chain="mainnet")

        assert result.source_available is True
        assert result.fetch_tier == "etherscan"
        assert result.contract_name == "Foo"
        assert result.compiler_version == "v0.8.19+commit.7dd6d404"
        assert len(result.source_files) >= 1

    @patch("requests.Session.get")
    def test_unverified_source_returns_none(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "1",
            "message": "OK",
            "result": [
                {
                    "SourceCode": "Contract source code not verified",
                    "ABI": "Contract source code not verified",
                    "ContractName": "",
                    "CompilerVersion": "",
                }
            ],
        }
        mock_get.return_value = mock_resp

        fetcher = self._make_fetcher()
        # Falls through to Sourcify then bytecode-only
        with patch.object(fetcher, "_try_sourcify", return_value=None), \
             patch.object(fetcher, "_fetch_bytecode", return_value=None):
            result = fetcher.fetch("0x" + "a" * 40, chain="mainnet")

        assert result.source_available is False
        assert result.fetch_tier == "bytecode_only"

    @patch("requests.Session.get")
    def test_abi_parsed(self, mock_get):
        abi = json.dumps([
            {"type": "function", "name": "transfer",
             "inputs": [{"name": "to", "type": "address"},
                        {"name": "amount", "type": "uint256"}],
             "outputs": [{"name": "", "type": "bool"}],
             "stateMutability": "nonpayable"}
        ])
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_etherscan_response(
            source_code="contract Token {}", abi=abi
        )
        mock_get.return_value = mock_resp

        fetcher = self._make_fetcher()
        result = fetcher.fetch("0x" + "b" * 40, chain="mainnet")

        assert result.abi is not None
        assert isinstance(result.abi, list)
        assert result.abi[0]["name"] == "transfer"


class TestOnChainFetcherSourcify:
    @patch("requests.Session.get")
    def test_sourcify_fallback(self, mock_get):
        # First call (Etherscan) → not found
        etherscan_resp = MagicMock()
        etherscan_resp.status_code = 200
        etherscan_resp.json.return_value = {"status": "0", "message": "NOTOK", "result": []}

        # Second call (Sourcify) → success
        sourcify_resp = MagicMock()
        sourcify_resp.status_code = 200
        sourcify_resp.json.return_value = {
            "status": "perfect",
            "files": [
                {
                    "name": "Vault.sol",
                    "path": "contracts/Vault.sol",
                    "content": "// SPDX-License-Identifier: MIT\ncontract Vault {}",
                }
            ],
        }

        mock_get.side_effect = [etherscan_resp, sourcify_resp]

        fetcher = OnChainFetcher(timeout=5)
        result = fetcher.fetch("0x" + "c" * 40, chain="mainnet")

        assert result.source_available is True
        assert result.fetch_tier == "sourcify"
        assert "Vault.sol" in result.source_files

    @patch("requests.Session.get")
    def test_sourcify_404_falls_through(self, mock_get):
        etherscan_resp = MagicMock()
        etherscan_resp.status_code = 200
        etherscan_resp.json.return_value = {"status": "0", "result": []}

        sourcify_resp = MagicMock()
        sourcify_resp.status_code = 404

        mock_get.side_effect = [etherscan_resp, sourcify_resp]

        fetcher = OnChainFetcher(timeout=5)
        with patch.object(fetcher, "_fetch_bytecode", return_value="0x6080604052"):
            result = fetcher.fetch("0x" + "d" * 40, chain="mainnet")

        assert result.source_available is False
        assert result.bytecode == "0x6080604052"


class TestOnChainFetcherBytecodeOnly:
    @patch("requests.Session.post")
    def test_eth_getcode_called(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": "0x6080604052",
        }
        mock_post.return_value = mock_resp

        fetcher = OnChainFetcher(rpc_url="https://rpc.example.com", timeout=5)
        bytecode = fetcher._fetch_bytecode("0x" + "e" * 40, chain_id=1)

        assert bytecode == "0x6080604052"
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        payload = call_kwargs[1]["json"]
        assert payload["method"] == "eth_getCode"

    @patch("requests.Session.post")
    def test_eoa_returns_none(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": "0x"}
        mock_post.return_value = mock_resp

        fetcher = OnChainFetcher(rpc_url="https://rpc.example.com", timeout=5)
        bytecode = fetcher._fetch_bytecode("0x" + "f" * 40, chain_id=1)
        assert bytecode is None


class TestWriteSourcesToTempdir:
    def test_sol_files_written(self):
        source = OnChainSource(
            address="0x" + "a" * 40,
            chain_id=1,
            chain_name="mainnet",
            contract_name="MyToken",
            compiler_version="0.8.19",
            source_files={"MyToken.sol": "contract MyToken {}"},
            source_available=True,
            bytecode=None,
            abi=None,
            fetch_tier="etherscan",
        )
        fetcher = OnChainFetcher()
        tmpdir = fetcher.write_sources_to_tempdir(source)
        try:
            sol_file = tmpdir / "MyToken.sol"
            assert sol_file.exists()
            assert sol_file.read_text() == "contract MyToken {}"
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_bin_file_written_when_no_source(self):
        source = OnChainSource(
            address="0x" + "b" * 40,
            chain_id=1,
            chain_name="mainnet",
            contract_name="Unknown_0xbbbb",
            compiler_version=None,
            source_files={},
            source_available=False,
            bytecode="0x6080604052",
            abi=None,
            fetch_tier="bytecode_only",
        )
        fetcher = OnChainFetcher()
        tmpdir = fetcher.write_sources_to_tempdir(source)
        try:
            bin_file = tmpdir / "Unknown_0xbbbb.bin"
            assert bin_file.exists()
            assert bin_file.read_text() == "0x6080604052"
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_no_crash_when_bytecode_is_none(self):
        source = OnChainSource(
            address="0x" + "c" * 40,
            chain_id=1,
            chain_name="mainnet",
            contract_name="Ghost",
            compiler_version=None,
            source_files={},
            source_available=False,
            bytecode=None,
            abi=None,
            fetch_tier="bytecode_only",
        )
        fetcher = OnChainFetcher()
        tmpdir = fetcher.write_sources_to_tempdir(source)
        try:
            # Should produce an empty directory, not crash
            assert tmpdir.is_dir()
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)
