"""Unit tests for ERC4626 anti-condition (inflation-mitigation) detection."""

from __future__ import annotations

from pathlib import Path

from zeropath.core.inflation_guards import (
    detect_share_inflation_guards,
    summarize_guards,
)

REPO = Path(__file__).resolve().parents[1]
VULNERABLE = REPO / "examples" / "erc4626_inflation_fixture" / "src" / "VulnerableVault.sol"
PROTECTED = REPO / "examples" / "erc4626_protected_fixture" / "src" / "ProtectedVault.sol"


def _names(source: str) -> set[str]:
    return {hit.name for hit in detect_share_inflation_guards(source)}


def test_vulnerable_fixture_has_no_guards():
    # The benchmark vault reads the raw token balance and has no mitigation; it
    # must not trip any anti-condition or the happy path would be blocked.
    assert detect_share_inflation_guards(VULNERABLE.read_text()) == []


def test_protected_fixture_flags_virtual_shares_and_internal_accounting():
    names = _names(PROTECTED.read_text())
    assert "virtual_shares" in names
    assert "internal_accounting" in names


def test_empty_source_returns_no_guards():
    assert detect_share_inflation_guards("") == []


def test_raw_balance_total_assets_is_not_internal_accounting():
    source = "function totalAssets() public view returns (uint256) { return asset.balanceOf(address(this)); }"
    assert "internal_accounting" not in _names(source)


def test_stored_total_assets_is_internal_accounting():
    source = "function totalAssets() public view returns (uint256) { return _totalAssets; }"
    assert "internal_accounting" in _names(source)


def test_detects_dead_shares_mint_to_zero():
    source = "function deposit() external { _mint(address(0), MINIMUM_LIQUIDITY); }"
    assert "dead_shares" in _names(source)


def test_detects_first_deposit_guard():
    source = "function deposit(uint256 a) external returns (uint256 shares) { shares = a; require(shares > 0, 'zero'); }"
    assert "first_deposit_guard" in _names(source)


def test_detects_deposit_cap():
    source = "uint256 public depositCap; function deposit(uint256 a) external { require(a <= depositCap); }"
    assert "deposit_cap" in _names(source)


def test_vulnerable_ternary_is_not_a_first_deposit_guard():
    # `supply == 0 ? assets : ...` allows a tiny first deposit; it is the bug,
    # not a guard, and must not be flagged.
    source = "function convertToShares(uint256 assets) public view returns (uint256) { uint256 supply = totalSupply; return supply == 0 ? assets : assets * supply / totalAssets(); }"
    assert _names(source) == set()


def test_summarize_guards_lists_names_with_confidence():
    hits = detect_share_inflation_guards(PROTECTED.read_text())
    summary = summarize_guards(hits)
    assert "virtual_shares (heuristic)" in summary
    assert summarize_guards([]) == "none detected"
