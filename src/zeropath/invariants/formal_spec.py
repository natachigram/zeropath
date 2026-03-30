"""
Formal invariant specification generator.

Translates a detected Invariant into machine-checkable format strings
compatible with:
  - Halmos  (symbolic execution — Python assert-style)
  - Certora CVL (Certora Verification Language rules)

These are template-based: each InvariantType has a family of spec
templates parameterised by the contracts/variables/functions involved.

Phase 5 consumes Halmos specs directly.
Phase 2 produces them so they travel with every Invariant object.
"""

from __future__ import annotations

from typing import Optional

from zeropath.invariants.models import (
    FormalSpec,
    InvariantType,
    ProtocolPattern,
)


# ---------------------------------------------------------------------------
# Halmos spec templates
# ---------------------------------------------------------------------------

# Placeholders:
#   {contract}   — contract name
#   {func}       — function name
#   {var}        — state variable name
#   {oracle}     — oracle contract name
#   {ratio}      — collateral ratio (e.g. 1.5)

_HALMOS_TEMPLATES: dict[InvariantType, str] = {
    InvariantType.VALUE_CONSERVATION: (
        "assert balanceBefore + deposited(tx) >= balanceAfter + withdrawn(tx), "
        "\"Value conservation violated: more left than entered\""
    ),
    InvariantType.BALANCE_CONSISTENCY: (
        "assert sum(balanceOf[u] for u in allUsers) == totalSupply(), "
        "\"Balance inconsistency: sum of balances != totalSupply\""
    ),
    InvariantType.COLLATERALIZATION: (
        "assert collateralValue(account) >= debtValue(account) * MIN_COLLATERAL_RATIO, "
        "\"Under-collateralisation: collateral < debt * ratio\""
    ),
    InvariantType.ORACLE_MANIPULATION: (
        "assert priceAfterTx == priceBefore or blockNumber(priceAfterTx) > blockNumber(tx), "
        "\"Oracle price changed within same block as state mutation\""
    ),
    InvariantType.ACCESS_CONTROL: (
        "assert msg.sender == owner() or hasRole(ROLE, msg.sender), "
        "\"Privilege escalation: caller lacks required role\""
    ),
    InvariantType.REENTRANCY: (
        "assert not reentrant, "
        "\"Reentrancy: external call before state update\""
    ),
    InvariantType.FLASH_LOAN_SAFETY: (
        "assert balanceOf(protocol) >= balanceBefore(protocol), "
        "\"Flash loan safety: protocol balance decreased after atomic tx\""
    ),
    InvariantType.SHARE_ACCOUNTING: (
        "assert convertToAssets(convertToShares(amount)) <= amount, "
        "\"Share rounding: round-trip conversion yields more than deposited\""
    ),
    InvariantType.GOVERNANCE_SAFETY: (
        "assert block.number >= proposalEta(proposalId) + TIMELOCK_DELAY, "
        "\"Governance timelock: execution before delay elapsed\""
    ),
    InvariantType.CROSS_PROTOCOL: (
        "assert protocolA.price() == oraclePrice and not atomicallyManipulated(tx), "
        "\"Cross-protocol: external price unchanged within composability window\""
    ),
    InvariantType.LIQUIDITY_CONSERVATION: (
        "assert reserve0After * reserve1After >= reserve0Before * reserve1Before, "
        "\"AMM invariant: k decreased after swap\""
    ),
}

# ---------------------------------------------------------------------------
# Certora CVL rule templates
# ---------------------------------------------------------------------------

_CVL_TEMPLATES: dict[InvariantType, str] = {
    InvariantType.VALUE_CONSERVATION: (
        "rule valueConservation(env e, method f) {\n"
        "    uint256 balBefore = nativeBalances[currentContract];\n"
        "    calldataarg args;\n"
        "    f(e, args);\n"
        "    uint256 balAfter = nativeBalances[currentContract];\n"
        "    assert balAfter >= balBefore - withdrawnInTx(e), \"Value conservation\"; }"
    ),
    InvariantType.BALANCE_CONSISTENCY: (
        "invariant balanceConsistency()\n"
        "    sumOfBalances() == totalSupply()\n"
        "    filtered { f -> !f.isView }"
    ),
    InvariantType.COLLATERALIZATION: (
        "rule collateralizationSafe(env e, address account) {\n"
        "    require isHealthy(e, account);\n"
        "    method f; calldataarg args;\n"
        "    f(e, args);\n"
        "    assert isHealthy(e, account) || wasLiquidated(e, account), \"Under-collateralised\"; }"
    ),
    InvariantType.ORACLE_MANIPULATION: (
        "rule oracleNotManipulatedInBlock(env e) {\n"
        "    uint256 p1 = getPrice(e);\n"
        "    method f; calldataarg args;\n"
        "    f(e, args);\n"
        "    uint256 p2 = getPrice(e);\n"
        "    assert p1 == p2 || e.block.number > lastPriceUpdateBlock(), \"Oracle changed in block\"; }"
    ),
    InvariantType.ACCESS_CONTROL: (
        "rule onlyAuthorisedCanCall(env e) {\n"
        "    require !isAuthorised(e.msg.sender);\n"
        "    method f;\n"
        "    calldataarg args;\n"
        "    f@withrevert(e, args);\n"
        "    assert lastReverted, \"Unauthorised caller succeeded\"; }"
    ),
    InvariantType.REENTRANCY: (
        "rule noReentrancy(env e) {\n"
        "    require !inExecution();\n"
        "    method f; calldataarg args;\n"
        "    f(e, args);\n"
        "    assert !reentrantCallDetected(), \"Reentrancy detected\"; }"
    ),
    InvariantType.FLASH_LOAN_SAFETY: (
        "rule flashLoanSafe(env e) {\n"
        "    uint256 balBefore = protocolBalance(e);\n"
        "    method f; calldataarg args;\n"
        "    f(e, args);\n"
        "    assert protocolBalance(e) >= balBefore, \"Protocol drained\"; }"
    ),
    InvariantType.SHARE_ACCOUNTING: (
        "rule shareRoundTripNonInflating(env e, uint256 assets) {\n"
        "    uint256 shares = convertToShares(e, assets);\n"
        "    assert convertToAssets(e, shares) <= assets, \"Share inflation\"; }"
    ),
    InvariantType.GOVERNANCE_SAFETY: (
        "rule timelockEnforced(env e, uint256 proposalId) {\n"
        "    require e.block.timestamp < proposalEta(proposalId) + timelockDelay();\n"
        "    execute@withrevert(e, proposalId);\n"
        "    assert lastReverted, \"Governance executed before timelock\"; }"
    ),
    InvariantType.LIQUIDITY_CONSERVATION: (
        "invariant ammKInvariant()\n"
        "    reserve0() * reserve1() >= kLast()\n"
        "    filtered { f -> !f.isView }"
    ),
    InvariantType.CROSS_PROTOCOL: (
        "rule crossProtocolIntegrity(env e) {\n"
        "    uint256 extPriceBefore = externalOracle.price(e);\n"
        "    method f; calldataarg args;\n"
        "    f(e, args);\n"
        "    assert externalOracle.price(e) == extPriceBefore, \"Cross-protocol price drift\"; }"
    ),
}

# ---------------------------------------------------------------------------
# Natural-language templates
# ---------------------------------------------------------------------------

_NL_TEMPLATES: dict[InvariantType, str] = {
    InvariantType.VALUE_CONSERVATION: (
        "Total assets entering the protocol must equal total assets leaving plus any fees. "
        "No single transaction may remove more value than it deposits."
    ),
    InvariantType.BALANCE_CONSISTENCY: (
        "The sum of all individual user balances must equal totalSupply() at all times. "
        "No mint or burn operation may create an inconsistency."
    ),
    InvariantType.COLLATERALIZATION: (
        "Every borrower's collateral value must exceed their debt value multiplied by the "
        "minimum collateral ratio. Under-collateralised positions must be immediately liquidatable."
    ),
    InvariantType.ORACLE_MANIPULATION: (
        "Price oracle reads used for state-changing decisions must not be manipulable within "
        "a single block. Single-block spot price reads in state-mutating functions are HIGH risk."
    ),
    InvariantType.ACCESS_CONTROL: (
        "Privileged operations (admin, upgrade, pause, mint) must only be callable by "
        "addresses with the correct role or ownership. No privilege escalation path must exist."
    ),
    InvariantType.REENTRANCY: (
        "External calls in state-mutating functions must not allow re-entry before all state "
        "updates are completed. CEI (Checks-Effects-Interactions) must be strictly followed."
    ),
    InvariantType.FLASH_LOAN_SAFETY: (
        "Flash-loan-funded atomic transactions must not permanently reduce the protocol's "
        "net asset balance. Any funds borrowed within a transaction must be returned."
    ),
    InvariantType.SHARE_ACCOUNTING: (
        "The share-to-asset exchange rate must never increase unexpectedly within a single "
        "transaction. Round-trip conversions (assets→shares→assets) must return ≤ original amount."
    ),
    InvariantType.GOVERNANCE_SAFETY: (
        "Governance proposals must not be executable in the same block as they pass. "
        "A mandatory time-lock delay must separate proposal passage from execution."
    ),
    InvariantType.CROSS_PROTOCOL: (
        "Invariants that span multiple protocols must hold simultaneously. External price "
        "feeds and liquidity state from dependency protocols must be verified before use."
    ),
    InvariantType.LIQUIDITY_CONSERVATION: (
        "The AMM constant product invariant (k = x * y) must not decrease after any swap. "
        "Fees may increase k but no operation should decrease it."
    ),
}


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


class FormalSpecGenerator:
    """
    Generate FormalSpec objects for a given invariant type and context.

    Usage::

        gen = FormalSpecGenerator()
        spec = gen.generate(InvariantType.ORACLE_MANIPULATION, pattern=pattern)
    """

    def generate(
        self,
        invariant_type: InvariantType,
        pattern: Optional[ProtocolPattern] = None,
    ) -> FormalSpec:
        """
        Generate a FormalSpec for the given invariant type.

        The pattern is used to optionally fill in specific variable names
        where they are known.
        """
        halmos = _HALMOS_TEMPLATES.get(invariant_type)
        cvl = _CVL_TEMPLATES.get(invariant_type)
        nl = _NL_TEMPLATES.get(
            invariant_type,
            f"Invariant of type {invariant_type.value} must hold.",
        )

        if pattern and halmos:
            halmos = _fill_context(halmos, invariant_type, pattern)

        return FormalSpec(
            halmos=halmos,
            certora_cvl=cvl,
            natural_language=nl,
        )


# ---------------------------------------------------------------------------
# Context filling (best-effort variable substitution)
# ---------------------------------------------------------------------------


def _fill_context(
    template: str,
    invariant_type: InvariantType,
    pattern: ProtocolPattern,
) -> str:
    """
    Best-effort substitution of known variable/function names into a template.
    Falls back to generic placeholders if specifics are unavailable.
    """
    replacements: dict[str, str] = {}

    if pattern.balance_vars:
        replacements["{var}"] = pattern.balance_vars[0]
    if pattern.oracle_vars:
        replacements["{oracle}"] = pattern.oracle_vars[0]
    if pattern.deposit_functions:
        replacements["{func}"] = pattern.deposit_functions[0]

    result = template
    for placeholder, value in replacements.items():
        result = result.replace(placeholder, value)

    return result
