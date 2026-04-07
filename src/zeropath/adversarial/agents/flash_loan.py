"""
FlashLoanAgent — Phase 3 adversarial agent.

Generates attack hypotheses for:
  - Flash loan + oracle manipulation
  - Flash loan + balance check bypass
  - Flash loan + governance capture
  - Flash loan + AMM price distortion
  - Same-block borrow-and-drain patterns
"""

from __future__ import annotations

import logging

from zeropath.adversarial.base import BaseAdversarialAgent
from zeropath.adversarial.models import AttackClass, AttackHypothesis, ConditionType
from zeropath.invariants.models import (
    Invariant,
    InvariantType,
    OracleManipulationRisk,
    ProtocolPattern,
)
from zeropath.models import ProtocolGraph

logger = logging.getLogger(__name__)

_PROVIDERS = ["Aave V3", "Balancer", "Uniswap V3", "dYdX", "Euler"]
_HISTORICAL = [
    "bZx ($350K, 2019)",
    "Harvest Finance ($34M, 2020)",
    "Pancake Bunny ($45M, 2021)",
    "Cream Finance ($18M, 2021)",
    "Euler Finance ($197M, 2023)",
]


class FlashLoanAgent(BaseAdversarialAgent):
    """Generates flash loan attack hypotheses."""

    name = "FlashLoanAgent"
    attack_class = AttackClass.FLASH_LOAN
    relevant_invariant_types = [
        InvariantType.FLASH_LOAN_SAFETY,
        InvariantType.ORACLE_MANIPULATION,
        InvariantType.VALUE_CONSERVATION,
        InvariantType.BALANCE_CONSISTENCY,
        InvariantType.COLLATERALIZATION,
    ]

    def analyse_invariant(
        self,
        invariant: Invariant,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[AttackHypothesis]:
        hypotheses: list[AttackHypothesis] = []

        has_oracle_risk = any(
            d.manipulation_risk in (OracleManipulationRisk.HIGH, OracleManipulationRisk.MEDIUM)
            for d in invariant.oracle_dependencies
        )
        has_governance = bool(pattern.governance_functions)
        has_amm = any(t.value == "amm" for t in pattern.protocol_types)

        if has_oracle_risk:
            hypotheses.append(self._oracle_price_attack(invariant, pattern))

        if pattern.borrow_functions and has_oracle_risk:
            hypotheses.append(self._collateral_inflation_drain(invariant, pattern))

        if has_governance:
            hypotheses.append(self._governance_capture(invariant, pattern))

        if has_amm:
            hypotheses.append(self._amm_reserve_drain(invariant, pattern))

        # Always add generic flash loan + rebalance attack if protocol has deposit/withdraw
        if pattern.deposit_functions and pattern.withdraw_functions:
            hypotheses.append(self._balance_check_bypass(invariant, pattern))

        return hypotheses

    # ------------------------------------------------------------------

    def _oracle_price_attack(self, invariant, pattern) -> AttackHypothesis:
        dep = next(
            (d for d in invariant.oracle_dependencies
             if d.manipulation_risk == OracleManipulationRisk.HIGH), None
        )
        oracle = dep.oracle_contract if dep else "OracleContract"
        fn = dep.function_name if dep else (pattern.borrow_functions or ["borrow"])[0]
        contract = (invariant.contracts_involved or ["Target"])[0]

        steps = [
            self._step(1, "Execute multi-asset flash loan from Aave V3",
                       "Borrow maximum liquidity atomically",
                       target_contract="AaveV3", target_function="flashLoan"),
            self._step(2, f"Swap flash-loaned assets into {oracle} pool — skew spot price",
                       "Move pool reserves to desired direction within same block",
                       target_contract=oracle),
            self._step(3, f"Call `{fn}()` while oracle reads distorted price",
                       "Protocol values assets at manipulated price",
                       target_contract=contract, target_function=fn),
            self._step(4, f"Reverse swap to restore {oracle} reserves",
                       "Minimise permanent capital requirement",
                       target_contract=oracle),
            self._step(5, "Repay flash loan (principal + 0.09% fee)",
                       "Close transaction; retain profit",
                       target_contract="AaveV3"),
        ]
        preconditions = [
            self._precondition(ConditionType.ORACLE_READ_SINGLE_BLOCK,
                               "Oracle reads spot price in same transaction block",
                               is_met=dep.is_single_block if dep else None),
            self._precondition(ConditionType.FLASH_LOAN_AVAILABLE,
                               f"Flash loan providers available: {', '.join(_PROVIDERS[:3])}",
                               is_met=True),
        ]
        profit = self._profit(
            "Borrow/withdraw at inflated price, repay at true price",
            asset="ERC20",
            scales_with_tvl=True,
        )
        poc = f"""// Foundry flash loan PoC
contract Exploit is IFlashLoanReceiver {{
    function attack() external {{
        address[] memory assets = new address[](1);
        assets[0] = WETH;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = MAX_FLASH;
        AAVE_V3.flashLoan(address(this), assets, amounts, ...);
    }}

    function executeOperation(...) external returns (bool) {{
        // Skew oracle
        I{oracle}(ORACLE).swap(wethAmount, ...);
        // Exploit
        I{contract}(TARGET).{fn}(...);
        // Restore
        I{oracle}(ORACLE).swap(wethAmount, ...);
        return true;
    }}
}}"""
        return self._make_hypothesis(
            invariant,
            title=f"Flash loan oracle attack: skew {oracle} → exploit {fn}()",
            attack_class=AttackClass.FLASH_LOAN,
            narrative=(
                f"Attacker borrows large capital via flash loan, manipulates `{oracle}` spot price "
                f"within the same block, calls `{fn}` at distorted price, then unwinds — all atomically."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.85,
            historical_protocols=_HISTORICAL,
            historical_loss=197_000_000,
            poc_sketch=poc,
            suggested_fix="Replace spot oracle with Chainlink or TWAP >= 30 min. Add per-block borrow limits.",
        )

    def _collateral_inflation_drain(self, invariant, pattern) -> AttackHypothesis:
        deposit_fn = (pattern.deposit_functions or ["deposit"])[0]
        borrow_fn = (pattern.borrow_functions or ["borrow"])[0]
        contract = (invariant.contracts_involved or ["Lending"])[0]

        steps = [
            self._step(1, "Flash loan large amount of the collateral asset",
                       "Need capital proportional to desired borrow amount",
                       target_function="flashLoan"),
            self._step(2, f"Deposit all flash-loaned tokens as collateral via `{deposit_fn}()`",
                       "Inflate collateral position",
                       target_contract=contract, target_function=deposit_fn),
            self._step(3, "Manipulate oracle to report inflated collateral price",
                       "Collateral appears worth more than deposited"),
            self._step(4, f"Borrow maximum against inflated collateral via `{borrow_fn}()`",
                       "Extract more value than deposited",
                       target_contract=contract, target_function=borrow_fn),
            self._step(5, "Leave collateral (worth less than loan) and repay flash loan",
                       "Net profit = borrowed amount − true collateral value − flash fee",
                       target_function="repay"),
        ]
        preconditions = [
            self._precondition(ConditionType.ORACLE_READ_SINGLE_BLOCK,
                               "Collateral valuation uses manipulable spot price", is_met=None),
            self._precondition(ConditionType.FLASH_LOAN_AVAILABLE,
                               "Sufficient liquidity available via flash loan", is_met=True),
        ]
        profit = self._profit(
            f"Borrow > true collateral via {borrow_fn}; protocol left with bad debt",
            asset="ERC20",
        )
        return self._make_hypothesis(
            invariant,
            title=f"Flash loan collateral inflation → drain via {borrow_fn}()",
            attack_class=AttackClass.FLASH_LOAN,
            narrative=(
                f"Flash-loan funds deposited as collateral. Oracle manipulated to inflate "
                f"apparent collateral value. Max borrow extracted. Protocol left with bad debt."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.80,
            historical_protocols=_HISTORICAL[:3],
            historical_loss=34_000_000,
            suggested_fix="Use TWAPs for collateral valuation. Cap single-block borrows. Add liquidation incentives.",
        )

    def _governance_capture(self, invariant, pattern) -> AttackHypothesis:
        gov_fn = (pattern.governance_functions or ["vote"])[0]
        exec_fn = next(
            (f for f in pattern.governance_functions if "execute" in f.lower()), "execute"
        )
        contract = (invariant.contracts_involved or ["Governance"])[0]

        steps = [
            self._step(1, "Flash loan maximum governance tokens",
                       "Acquire voting supermajority within single block",
                       target_function="flashLoan"),
            self._step(2, f"Call `{gov_fn}()` with all flash-loaned tokens to pass malicious proposal",
                       "Instant supermajority vote — no snapshot protection",
                       target_contract=contract, target_function=gov_fn),
            self._step(3, f"Call `{exec_fn}()` immediately (no timelock)",
                       "Execute malicious proposal in same transaction",
                       target_contract=contract, target_function=exec_fn),
            self._step(4, "Proposal drains treasury, mints tokens, or upgrades contracts",
                       "Full protocol capture"),
            self._step(5, "Repay flash loan",
                       "Return governance tokens; keep stolen assets",
                       target_function="repay"),
        ]
        preconditions = [
            self._precondition(ConditionType.GOVERNANCE_TOKEN_AVAILABLE,
                               "Governance tokens available via flash loan or DEX",
                               is_met=True),
            self._precondition(ConditionType.NO_TIMELOCK,
                               "No timelock delay between proposal pass and execution",
                               is_met=not pattern.has_timelock),
            self._precondition(ConditionType.FLASH_LOAN_AVAILABLE,
                               "Governance token flash loan available", is_met=True),
        ]
        profit = self._profit("Full treasury capture via malicious governance proposal",
                               asset="ERC20", scales_with_tvl=True)
        return self._make_hypothesis(
            invariant,
            title=f"Flash loan governance capture — instant voting in {gov_fn}() with no timelock",
            attack_class=AttackClass.GOVERNANCE,
            narrative=(
                f"Flash-loaned governance tokens give attacker instant supermajority.  "
                f"Without snapshot-based voting or timelock, a malicious proposal can be "
                f"proposed, voted, and executed in a single transaction."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.88 if not pattern.has_timelock else 0.40,
            historical_protocols=["Beanstalk ($182M, 2022)"],
            historical_loss=182_000_000,
            suggested_fix=(
                "Use snapshot-based voting (getPastVotes). Add timelock >= 48 hours. "
                "Use vote-weight snapshots at proposal creation block."
            ),
        )

    def _amm_reserve_drain(self, invariant, pattern) -> AttackHypothesis:
        swap_fn = (pattern.swap_functions or ["swap"])[0]
        contract = (invariant.contracts_involved or ["AMM"])[0]

        steps = [
            self._step(1, "Flash loan token A",
                       "Need large capital to skew reserves significantly",
                       target_function="flashLoan"),
            self._step(2, f"Swap all token A for token B via `{swap_fn}()` — skew x*y=k reserves",
                       "Drive token B price up, token A price down",
                       target_contract=contract, target_function=swap_fn),
            self._step(3, "Call add/removeLiquidity or borrow against distorted reserves",
                       "Exploit the temporary price imbalance"),
            self._step(4, "Swap token B back to token A at worse price",
                       "Unwind at cost; profit from intermediate exploit"),
            self._step(5, "Repay flash loan",
                       "Close transaction",
                       target_function="repay"),
        ]
        preconditions = [
            self._precondition(ConditionType.FLASH_LOAN_AVAILABLE,
                               "Flash loan large enough to meaningfully skew reserves",
                               is_met=True),
            self._precondition(ConditionType.ORACLE_READ_SINGLE_BLOCK,
                               "Protocol reads spot reserves (not TWAP) for pricing",
                               is_met=None),
        ]
        profit = self._profit("Arbitrage from distorted AMM reserve ratio", asset="ERC20")
        return self._make_hypothesis(
            invariant,
            title=f"Flash loan AMM reserve manipulation via {swap_fn}()",
            attack_class=AttackClass.FLASH_LOAN,
            narrative=(
                f"Large flash loan distorts AMM reserve ratio, enabling profitable interactions "
                f"with protocols that read spot reserves for pricing or liquidity calculations."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.65,
            historical_protocols=_HISTORICAL[:2],
            suggested_fix="Use TWAP for all AMM-dependent pricing. Add reserve change rate limits.",
        )

    def _balance_check_bypass(self, invariant, pattern) -> AttackHypothesis:
        deposit_fn = (pattern.deposit_functions or ["deposit"])[0]
        withdraw_fn = (pattern.withdraw_functions or ["withdraw"])[0]
        contract = (invariant.contracts_involved or ["Vault"])[0]

        steps = [
            self._step(1, f"Flash loan funds and deposit via `{deposit_fn}()`",
                       "Temporarily inflate protocol's total deposits",
                       target_contract=contract, target_function=deposit_fn),
            self._step(2, "Protocol recalculates balances/shares with inflated total",
                       "Share price or rate temporarily distorted"),
            self._step(3, "Other users' shares now worth less (inflation attack) OR attacker's more",
                       "Exploit accounting asymmetry"),
            self._step(4, f"Withdraw via `{withdraw_fn}()` at favourable rate",
                       "Extract more than deposited",
                       target_contract=contract, target_function=withdraw_fn),
            self._step(5, "Repay flash loan",
                       "Net profit from exploited accounting",
                       target_function="repay"),
        ]
        preconditions = [
            self._precondition(ConditionType.FLASH_LOAN_AVAILABLE,
                               "Flash loan available for the deposited asset", is_met=True),
            self._precondition(ConditionType.CUSTOM,
                               "Protocol has no per-block deposit limits or share calculation protection",
                               is_met=not pattern.has_reentrancy_guard),
        ]
        profit = self._profit("Extract excess value via accounting asymmetry", asset="ERC20")
        return self._make_hypothesis(
            invariant,
            title=f"Flash loan balance inflation via {deposit_fn}() → drain via {withdraw_fn}()",
            attack_class=AttackClass.FLASH_LOAN,
            narrative=(
                f"Flash-loaned funds temporarily inflate protocol's total deposits, "
                f"distorting share accounting.  Attacker extracts excess value before repaying."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.55,
            historical_protocols=["Harvest Finance ($34M, 2020)"],
            historical_loss=34_000_000,
            suggested_fix=(
                "Add virtual shares / dead shares offset.  Check share price stability "
                "within single blocks.  Use ERC4626 rounding in protocol's favour."
            ),
        )
