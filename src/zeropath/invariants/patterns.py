"""
DeFi protocol pattern detector.

Analyses a ProtocolGraph and produces a ProtocolPattern describing which
DeFi archetypes are present.  The ProtocolPattern is consumed by every
invariant detector to avoid repeated graph traversal.

Detection strategy:
  - Function name matching (canonical DeFi vocabulary)
  - State variable name matching (balance, supply, oracle, shares, debt)
  - Modifier detection (nonReentrant, onlyOwner, onlyRole)
  - External dependency interface matching (ERC20, Uniswap, Chainlink)
  - Proxy type detection (upgradeable)

All matching is case-insensitive substring matching to handle naming
variants (e.g. "userDeposit", "depositETH", "_deposit", "DEPOSIT").
"""

import re
from typing import Iterable

from zeropath.models import (
    Contract,
    ExternalDependency,
    Function,
    ProtocolGraph,
    ProxyType,
    StateVariable,
)
from zeropath.invariants.models import DeFiProtocolType, ProtocolPattern


# ---------------------------------------------------------------------------
# Keyword dictionaries
# ---------------------------------------------------------------------------

_DEPOSIT_KW = {"deposit", "provide", "supply", "addliquidity", "addcollateral", "stake"}
_WITHDRAW_KW = {"withdraw", "redeem", "removeliquidity", "unstake", "exit", "pull"}
_BORROW_KW = {"borrow", "loan", "flashloan", "flashborrow", "lend"}
_REPAY_KW = {"repay", "repayborrow", "reimburse", "settle"}
_LIQUIDATE_KW = {"liquidate", "liquidatecall", "seize", "foreclose"}
_SWAP_KW = {"swap", "exchange", "trade", "sell", "buy"}
_MINT_KW = {"mint", "issue", "create", "forge"}
_BURN_KW = {"burn", "destroy", "redeem", "retire"}
_STAKE_KW = {"stake", "lock", "vest", "deposit"}
_GOVERNANCE_KW = {"propose", "vote", "queue", "execute", "cancel", "castVote", "timelock"}
_FLASH_LOAN_KW = {"flashloan", "flash", "flashborrow", "executeflash", "onflashloan", "executeoperation"}
_ADMIN_KW = {"admin", "owner", "pause", "unpause", "setfee", "setoracle", "upgrade", "initialize", "setrole", "grant", "revoke"}

_BALANCE_VAR_KW = {"balance", "balances", "userbalance", "accountbalance"}
_SUPPLY_VAR_KW = {"totalsupply", "totaltokens", "totaldeposited", "totalassets"}
_ORACLE_VAR_KW = {"oracle", "pricefeed", "aggregator", "priceoracle", "feed", "twap"}
_SHARE_VAR_KW = {"shares", "totalshares", "sharesof", "lptoken", "sptoken"}
_DEBT_VAR_KW = {"debt", "borrows", "totalborrows", "totaldebt", "outstanding"}
_COLLATERAL_VAR_KW = {"collateral", "collaterals", "collateralamount", "pledged"}
_FEE_VAR_KW = {"fee", "fees", "protocolFee", "performanceFee", "reserveFee"}
_TIMELOCK_VAR_KW = {"timelock", "delay", "eta", "timelockcontroller", "executiondelay"}

_ERC20_FUNCTIONS = {"transfer", "transferfrom", "balanceof", "allowance", "approve", "totalsupply"}
_ERC721_FUNCTIONS = {"safetransferfrom", "ownerof", "tokenuri", "getapproved", "setapprovalforall"}
_ERC4626_FUNCTIONS = {"converttoshares", "converttoassets", "maxdeposit", "previewdeposit", "previewwithdraw"}

# Known interfaces that signal oracle usage
_ORACLE_INTERFACES = {"chainlink", "aggregatorv3interface", "aggregatorinterface", "keepercompatible",
                      "iuniswapv2pair", "iuniswapv3pool", "iband", "itelloracle", "iumaoptimisticoracle"}


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------


class DeFiPatternDetector:
    """
    Scan a ProtocolGraph and produce a ProtocolPattern.

    Usage::

        detector = DeFiPatternDetector()
        pattern = detector.detect(graph)
    """

    def detect(self, graph: ProtocolGraph) -> ProtocolPattern:
        """Analyse the graph and return a ProtocolPattern."""
        pattern = ProtocolPattern()

        func_names_lower = {f.name.lower(): f for f in graph.functions}
        var_names_lower  = {v.name.lower(): v for v in graph.state_variables}

        self._detect_function_buckets(graph.functions, pattern)
        self._detect_state_var_buckets(graph.state_variables, pattern)
        self._detect_security_features(graph.functions, graph.state_variables, pattern)
        self._detect_external_oracle_deps(graph.external_dependencies, pattern)
        self._detect_upgradeable(graph.contracts, pattern)
        self._classify_protocol_types(func_names_lower, var_names_lower, pattern)

        return pattern

    # ------------------------------------------------------------------
    # Function bucket detection
    # ------------------------------------------------------------------

    def _detect_function_buckets(
        self,
        functions: list[Function],
        pattern: ProtocolPattern,
    ) -> None:
        """Classify functions into DeFi buckets by name keyword matching."""
        for func in functions:
            name_lower = func.name.lower()

            if _matches_any(name_lower, _DEPOSIT_KW):
                pattern.deposit_functions.append(func.name)
            if _matches_any(name_lower, _WITHDRAW_KW):
                pattern.withdraw_functions.append(func.name)
            if _matches_any(name_lower, _MINT_KW) and not _matches_any(name_lower, {"comment"}):
                pattern.mint_functions.append(func.name)
            if _matches_any(name_lower, _BURN_KW):
                pattern.burn_functions.append(func.name)
            if _matches_any(name_lower, _BORROW_KW):
                pattern.borrow_functions.append(func.name)
            if _matches_any(name_lower, _REPAY_KW):
                pattern.repay_functions.append(func.name)
            if _matches_any(name_lower, _LIQUIDATE_KW):
                pattern.liquidate_functions.append(func.name)
            if _matches_any(name_lower, _SWAP_KW):
                pattern.swap_functions.append(func.name)
            if _matches_any(name_lower, _STAKE_KW):
                pattern.stake_functions.append(func.name)
            if _matches_any(name_lower, _GOVERNANCE_KW):
                pattern.governance_functions.append(func.name)
            if _matches_any(name_lower, _FLASH_LOAN_KW):
                pattern.flash_loan_functions.append(func.name)
                pattern.has_flash_loan = True
            if _matches_any(name_lower, _ADMIN_KW):
                pattern.admin_functions.append(func.name)
            if func.is_payable:
                pattern.payable_functions.append(func.name)

        # ERC4626 — requires multiple matching functions
        all_lower = {f.lower() for f in [func.name for func in functions]}
        if all_lower & _ERC4626_FUNCTIONS:
            pattern.is_erc4626 = True

    # ------------------------------------------------------------------
    # State variable bucket detection
    # ------------------------------------------------------------------

    def _detect_state_var_buckets(
        self,
        state_vars: list[StateVariable],
        pattern: ProtocolPattern,
    ) -> None:
        for var in state_vars:
            name_lower = var.name.lower()
            type_lower = var.type_.lower()

            if _matches_any(name_lower, _BALANCE_VAR_KW):
                pattern.balance_vars.append(var.name)
            if _matches_any(name_lower, _SUPPLY_VAR_KW):
                pattern.supply_vars.append(var.name)
            if _matches_any(name_lower, _ORACLE_VAR_KW) or _matches_any(type_lower, _ORACLE_INTERFACES):
                pattern.oracle_vars.append(var.name)
                pattern.has_oracle = True
            if _matches_any(name_lower, _SHARE_VAR_KW):
                pattern.share_vars.append(var.name)
            if _matches_any(name_lower, _DEBT_VAR_KW):
                pattern.debt_vars.append(var.name)
            if _matches_any(name_lower, _COLLATERAL_VAR_KW):
                pattern.collateral_vars.append(var.name)
            if _matches_any(name_lower, _FEE_VAR_KW):
                pattern.fee_vars.append(var.name)
            if _matches_any(name_lower, _TIMELOCK_VAR_KW):
                pattern.timelock_vars.append(var.name)
                pattern.has_timelock = True

    # ------------------------------------------------------------------
    # Security feature detection
    # ------------------------------------------------------------------

    def _detect_security_features(
        self,
        functions: list[Function],
        state_vars: list[StateVariable],
        pattern: ProtocolPattern,
    ) -> None:
        for func in functions:
            modifiers_lower = [m.lower() for m in func.modifiers]

            # Reentrancy guard
            if any("nonreentrant" in m or "reentrant" in m or "noreentrancy" in m
                   for m in modifiers_lower):
                pattern.has_reentrancy_guard = True

            # Access control
            if (func.access_control.only_owner
                    or func.access_control.only_role
                    or any("onlyowner" in m or "onlyrole" in m or "restricted" in m
                           or "auth" in m for m in modifiers_lower)):
                pattern.has_access_control = True

    # ------------------------------------------------------------------
    # External oracle dependency detection
    # ------------------------------------------------------------------

    def _detect_external_oracle_deps(
        self,
        deps: list[ExternalDependency],
        pattern: ProtocolPattern,
    ) -> None:
        for dep in deps:
            iface = (dep.interface or "").lower()
            name_lower = dep.name.lower()

            if (iface in _ORACLE_INTERFACES
                    or any(kw in name_lower for kw in {"oracle", "feed", "price", "aggregator", "twap"})):
                pattern.has_oracle = True
                if dep.name not in pattern.oracle_vars:
                    pattern.oracle_vars.append(dep.name)

    # ------------------------------------------------------------------
    # Upgradeability detection
    # ------------------------------------------------------------------

    def _detect_upgradeable(
        self,
        contracts: list[Contract],
        pattern: ProtocolPattern,
    ) -> None:
        for c in contracts:
            if c.proxy_type != ProxyType.NONE:
                pattern.is_upgradeable = True
                break

    # ------------------------------------------------------------------
    # Protocol type classification
    # ------------------------------------------------------------------

    def _classify_protocol_types(
        self,
        func_names_lower: dict[str, Function],
        var_names_lower: dict[str, StateVariable],
        pattern: ProtocolPattern,
    ) -> None:
        types: set[DeFiProtocolType] = set()

        # ERC-20
        if len(_ERC20_FUNCTIONS & set(func_names_lower)) >= 3:
            types.add(DeFiProtocolType.ERC20)
            pattern.is_erc20 = True

        # ERC-721
        if len(_ERC721_FUNCTIONS & set(func_names_lower)) >= 2:
            types.add(DeFiProtocolType.ERC721)
            pattern.is_erc721 = True

        # ERC-4626
        if pattern.is_erc4626:
            types.add(DeFiProtocolType.ERC4626)

        # Lending
        if pattern.borrow_functions and pattern.repay_functions:
            types.add(DeFiProtocolType.LENDING)
        elif pattern.liquidate_functions and (pattern.debt_vars or pattern.collateral_vars):
            types.add(DeFiProtocolType.LENDING)

        # AMM
        if pattern.swap_functions and (
            "reserves" in var_names_lower
            or "reserve0" in var_names_lower
            or "pool" in " ".join(var_names_lower)
        ):
            types.add(DeFiProtocolType.AMM)
        elif len(pattern.swap_functions) >= 2:
            types.add(DeFiProtocolType.AMM)

        # Staking
        if pattern.stake_functions and (
            "reward" in " ".join(func_names_lower)
            or "claim" in " ".join(func_names_lower)
        ):
            types.add(DeFiProtocolType.STAKING)

        # Governance
        if pattern.governance_functions and len(pattern.governance_functions) >= 2:
            types.add(DeFiProtocolType.GOVERNANCE)

        # Flash loan
        if pattern.has_flash_loan:
            types.add(DeFiProtocolType.FLASH_LOAN)

        # Oracle
        if pattern.has_oracle:
            types.add(DeFiProtocolType.ORACLE)

        if not types:
            types.add(DeFiProtocolType.UNKNOWN)

        pattern.protocol_types = list(types)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _matches_any(name: str, keywords: set[str]) -> bool:
    """Return True if name contains any keyword as a substring (case-insensitive)."""
    return any(kw in name for kw in keywords)
