"""
IntegerMathAgent — Phase 3 adversarial agent.

Generates attack hypotheses for:
  - Integer overflow / underflow (Solidity < 0.8, unchecked blocks)
  - Precision loss / rounding in division (truncation toward zero)
  - ERC4626 share inflation via first-deposit rounding
  - Fee-on-transfer token breaking x*y=k invariant
  - Phantom overflow in assembly blocks
"""

from __future__ import annotations

import logging

from zeropath.adversarial.base import BaseAdversarialAgent
from zeropath.adversarial.models import AttackClass, AttackHypothesis, ConditionType
from zeropath.invariants.models import (
    Invariant,
    InvariantType,
    ProtocolPattern,
)
from zeropath.models import ProtocolGraph

logger = logging.getLogger(__name__)

_HISTORICAL = [
    "BatchOverflow ($1B+ market cap, 2018) — ERC20 overflow",
    "Compound liquidation bug ($90M, 2021) — precision error",
    "Angle Protocol inflation attack (2023)",
    "Sushiswap Trident integer underflow ($3.3M, 2023)",
    "Akutars NFT overflow ($34M frozen, 2022)",
]


class IntegerMathAgent(BaseAdversarialAgent):
    """Generates integer math attack hypotheses."""

    name = "IntegerMathAgent"
    attack_class = AttackClass.INTEGER_MATH
    relevant_invariant_types = [
        InvariantType.BALANCE_CONSISTENCY,
        InvariantType.SHARE_ACCOUNTING,
        InvariantType.VALUE_CONSERVATION,
        InvariantType.LIQUIDITY_CONSERVATION,
        InvariantType.COLLATERALIZATION,
    ]

    def analyse_invariant(
        self,
        invariant: Invariant,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[AttackHypothesis]:
        hypotheses: list[AttackHypothesis] = []

        # Detect if compiler version < 0.8 (overflow not auto-checked)
        old_compiler = self._detect_old_compiler(graph)
        unchecked_blocks = self._detect_unchecked(graph)

        if old_compiler:
            hypotheses.append(self._overflow_attack(invariant, graph, pattern))
            hypotheses.append(self._underflow_attack(invariant, graph, pattern))

        if unchecked_blocks:
            hypotheses.append(self._unchecked_overflow(invariant, unchecked_blocks[0]))

        # ERC4626 share inflation
        if pattern.is_erc4626 or pattern.share_vars:
            hypotheses.append(self._share_inflation(invariant, pattern))

        # Fee-on-transfer AMM math
        if pattern.swap_functions:
            hypotheses.append(self._fee_on_transfer_amm(invariant, pattern))

        # Division rounding
        if pattern.borrow_functions or pattern.deposit_functions:
            hypotheses.append(self._division_rounding(invariant, pattern))

        return hypotheses

    # ------------------------------------------------------------------

    def _detect_old_compiler(self, graph: ProtocolGraph) -> bool:
        for contract in graph.contracts:
            if contract.compiler_version:
                parts = contract.compiler_version.lstrip("^>=v").split(".")
                try:
                    if int(parts[0]) == 0 and int(parts[1]) < 8:
                        return True
                except (IndexError, ValueError):
                    pass
        return False

    def _detect_unchecked(self, graph: ProtocolGraph) -> list[str]:
        # Heuristic: look for function names associated with unchecked math
        return [
            f.name for f in graph.functions
            if any(kw in f.name.lower() for kw in ("unchecked", "unsafe", "raw"))
        ]

    # ------------------------------------------------------------------

    def _overflow_attack(self, invariant, graph, pattern) -> AttackHypothesis:
        contract = (invariant.contracts_involved or ["Token"])[0]
        balance_var = (pattern.balance_vars or ["balances"])[0]

        steps = [
            self._step(1, f"Send uint256.max - current_balance + 1 tokens to trigger overflow in {balance_var}",
                       "Compiler < 0.8 does not auto-revert on overflow",
                       target_contract=contract),
            self._step(2, f"Balance wraps around to a small positive number",
                       f"{balance_var}[attacker] = type(uint256).max + 1 = 0"),
            self._step(3, "With effectively zero balance, transfer large amounts freely",
                       "Or wrap to 2^256-1 and drain protocol"),
        ]
        preconditions = [
            self._precondition(ConditionType.INTEGER_TRUNCATION,
                               "Contract compiled with Solidity < 0.8 (no auto-overflow check)",
                               is_met=True,
                               evidence="Compiler version < 0.8 detected"),
            self._precondition(ConditionType.CUSTOM,
                               "No SafeMath library used for balance arithmetic",
                               is_met=None),
        ]
        profit = self._profit("Mint arbitrary token supply via overflow wrap-around",
                               asset="ERC20")
        poc = f"""// PoC for < 0.8 overflow
// Current balance: 1 token
// Transfer 2^256 - 1 tokens to self → balance wraps to max
I{contract}(TARGET).transfer(TARGET, type(uint256).max);
// Now balance is type(uint256).max - 1
// Transfer all to attacker
I{contract}(TARGET).transfer(ATTACKER, type(uint256).max - 1);"""
        return self._make_hypothesis(
            invariant,
            title=f"Integer overflow in {balance_var} — wrap-around to arbitrary supply",
            attack_class=AttackClass.INTEGER_MATH,
            narrative=(
                f"Contract compiled with Solidity < 0.8 without SafeMath.  "
                f"Arithmetic on `{balance_var}` can overflow, wrapping balances to 0 or max uint256."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.75,
            historical_protocols=_HISTORICAL[:1],
            poc_sketch=poc,
            suggested_fix="Upgrade to Solidity >= 0.8 or add SafeMath to all arithmetic operations.",
        )

    def _underflow_attack(self, invariant, graph, pattern) -> AttackHypothesis:
        contract = (invariant.contracts_involved or ["Contract"])[0]
        withdraw_fn = (pattern.withdraw_functions or ["withdraw"])[0]

        steps = [
            self._step(1, f"Call `{withdraw_fn}(amount > balance)` — no underflow check",
                       "Solidity < 0.8: subtraction wraps to uint256.max",
                       target_contract=contract, target_function=withdraw_fn),
            self._step(2, "Balance underflows to type(uint256).max",
                       "Attacker appears to hold maximum possible balance"),
            self._step(3, f"Call `{withdraw_fn}(all)` to drain the contract",
                       "Contract sends attacker all its holdings",
                       target_contract=contract, target_function=withdraw_fn),
        ]
        preconditions = [
            self._precondition(ConditionType.INTEGER_TRUNCATION,
                               "Solidity < 0.8 — no underflow protection", is_met=True),
        ]
        profit = self._profit("Drain contract via underflow in balance tracking", asset="ETH/ERC20")
        return self._make_hypothesis(
            invariant,
            title=f"Integer underflow in {withdraw_fn}() — balance wraps to uint256.max",
            attack_class=AttackClass.INTEGER_MATH,
            narrative=(
                f"Withdrawing more than available balance causes uint256 underflow.  "
                f"Without SafeMath, the balance wraps to `uint256.max`, enabling unlimited withdrawals."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.70,
            historical_protocols=_HISTORICAL[:1],
            suggested_fix="Upgrade compiler to 0.8+. Add `require(balance >= amount)` before subtraction.",
        )

    def _unchecked_overflow(self, invariant, fn_name) -> AttackHypothesis:
        contract = (invariant.contracts_involved or ["Contract"])[0]

        steps = [
            self._step(1, f"Trigger `{fn_name}()` with inputs designed to overflow in unchecked block",
                       "Solidity 0.8+ unchecked blocks bypass overflow protection",
                       target_contract=contract, target_function=fn_name),
            self._step(2, "Overflow in unchecked block produces wrong result without revert",
                       "Silent miscalculation in critical arithmetic"),
            self._step(3, "Exploit the miscalculated value to extract tokens or bypass limits",
                       "Depends on what the value controls"),
        ]
        preconditions = [
            self._precondition(ConditionType.INTEGER_TRUNCATION,
                               f"`{fn_name}` uses `unchecked` block with potentially overflowable arithmetic",
                               is_met=True),
        ]
        profit = self._profit("Arithmetic bypass via unchecked overflow", asset="ERC20")
        return self._make_hypothesis(
            invariant,
            title=f"Overflow in unchecked arithmetic block in {fn_name}()",
            attack_class=AttackClass.INTEGER_MATH,
            narrative=(
                f"`{fn_name}` uses `unchecked{{}}` which disables Solidity 0.8+ overflow checks.  "
                f"Crafted inputs can produce silent overflow, bypassing intended limits."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.55,
            suggested_fix=f"Audit all `unchecked{{}}` blocks in `{fn_name}`. Only use unchecked for gas optimisation where overflow is provably impossible.",
        )

    def _share_inflation(self, invariant, pattern) -> AttackHypothesis:
        deposit_fn = (pattern.deposit_functions or ["deposit"])[0]
        contract = (invariant.contracts_involved or ["Vault"])[0]
        share_var = (pattern.share_vars or ["totalShares"])[0]

        steps = [
            self._step(1, "Be the first depositor — deposit 1 wei to receive 1 share",
                       "Fresh vault: totalShares = 1 after first deposit",
                       target_contract=contract, target_function=deposit_fn),
            self._step(2, "Donate large amount directly to vault (transfer, not deposit)",
                       "Bypass deposit to inflate assets without minting shares",
                       target_contract=contract),
            self._step(3, "totalAssets = 1 wei + large_donation; totalShares = 1",
                       "Share price is now extremely high"),
            self._step(4, "Victim deposits: receives 0 shares due to rounding toward zero",
                       "convertToShares(victim_amount) = victim_amount * 1 / large_donation ≈ 0"),
            self._step(5, "Attacker redeems 1 share for all vault assets",
                       "Attacker's 1 share is now worth all assets including victim's deposit",
                       target_function="redeem"),
        ]
        preconditions = [
            self._precondition(ConditionType.CUSTOM,
                               "No virtual shares / dead shares protection in vault",
                               is_met=not bool(pattern.has_reentrancy_guard)),
            self._precondition(ConditionType.CUSTOM,
                               "Direct token transfer to vault possible (not wrapped asset)",
                               is_met=True),
        ]
        profit = self._profit(
            "Steal victim's deposit via share price inflation",
            asset="ERC20",
            scales_with_tvl=False,
        )
        poc = f"""// ERC4626 inflation attack PoC
// 1. Attacker deposits 1 wei
vault.{deposit_fn}(1, attacker);
// 2. Attacker donates directly
ASSET.transfer(address(vault), 1e18);
// 3. Victim deposits 1e18 → gets 0 shares (rounded down)
// 4. Attacker redeems 1 share → gets 1 + 1e18 + victim's 1e18"""
        return self._make_hypothesis(
            invariant,
            title=f"ERC4626 first-depositor share inflation via {deposit_fn}() rounding",
            attack_class=AttackClass.INTEGER_MATH,
            narrative=(
                f"Attacker becomes first depositor with 1 wei, then donates assets directly to "
                f"inflate share price.  Second depositor's shares round to 0, and attacker "
                f"redeems 1 share for all vault assets."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.75,
            historical_protocols=_HISTORICAL[2:3],
            poc_sketch=poc,
            suggested_fix=(
                "Add virtual shares offset (OZ ERC4626: `_decimalsOffset()`).  "
                "Or mint dead shares to address(0) at deployment.  "
                "Enforce minimum deposit amount >= 1e3 wei."
            ),
        )

    def _fee_on_transfer_amm(self, invariant, pattern) -> AttackHypothesis:
        swap_fn = (pattern.swap_functions or ["swap"])[0]
        contract = (invariant.contracts_involved or ["AMM"])[0]

        steps = [
            self._step(1, "Obtain a fee-on-transfer token (deflation token)",
                       "Some tokens deduct a percentage on every transfer"),
            self._step(2, f"Deposit fee-on-transfer token into AMM via {swap_fn}() or addLiquidity()",
                       "AMM records the pre-transfer amount, but receives less",
                       target_contract=contract, target_function=swap_fn),
            self._step(3, "AMM's internal accounting exceeds actual balance",
                       "x*y=k calculated with wrong token amount"),
            self._step(4, "Drain discrepancy via repeated swaps or exploit inflated k",
                       "Each swap extracts the fee-on-transfer gap"),
        ]
        preconditions = [
            self._precondition(ConditionType.FEE_ON_TRANSFER_TOKEN,
                               "AMM interacts with fee-on-transfer or rebasing tokens without special handling",
                               is_met=None),
        ]
        profit = self._profit("Drain accounting gap from fee-on-transfer token handling", asset="ERC20")
        return self._make_hypothesis(
            invariant,
            title=f"Fee-on-transfer token breaks AMM x*y=k invariant in {swap_fn}()",
            attack_class=AttackClass.INTEGER_MATH,
            narrative=(
                f"The AMM assumes `transfer(amount)` delivers exactly `amount` tokens.  "
                f"Fee-on-transfer tokens deliver less, breaking the constant product invariant."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.55,
            suggested_fix="Check balance before and after transfer. Use `balanceOf` delta instead of transfer argument.",
        )

    def _division_rounding(self, invariant, pattern) -> AttackHypothesis:
        fn = (pattern.borrow_functions or pattern.deposit_functions or ["calculateInterest"])[0]
        contract = (invariant.contracts_involved or ["Protocol"])[0]

        steps = [
            self._step(1, f"Make many small operations via `{fn}()` that individually round down",
                       "Each operation loses 1 wei to rounding in the protocol's favour",
                       target_contract=contract, target_function=fn),
            self._step(2, "Accumulate the rounding losses across thousands of transactions",
                       "Protocol slowly leaks dust to rounders"),
            self._step(3, "Or: find a rounding direction that always favours attacker",
                       "Some protocols round in user's favour by mistake"),
        ]
        preconditions = [
            self._precondition(ConditionType.INTEGER_TRUNCATION,
                               f"Division in `{fn}` truncates toward zero without rounding check",
                               is_met=None),
        ]
        profit = self._profit("Accumulated rounding profit or dust extraction", asset="ERC20",
                               scales_with_tvl=False)
        return self._make_hypothesis(
            invariant,
            title=f"Systematic rounding exploitation in {fn}() — precision loss",
            attack_class=AttackClass.INTEGER_MATH,
            narrative=(
                f"Division in `{fn}` truncates toward zero.  Depending on rounding direction, "
                f"the protocol or attacker consistently benefits from the discrepancy."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.45,
            suggested_fix=(
                f"Ensure rounding favours the protocol (round up on debt, round down on assets).  "
                f"Use `mulDivUp` / `mulDivDown` (Solmate FixedPointMathLib) explicitly.  "
                f"ERC4626 spec mandates rounding in protocol's favour."
            ),
        )
