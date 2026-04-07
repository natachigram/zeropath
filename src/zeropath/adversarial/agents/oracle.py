"""
OracleManipulatorAgent — Phase 3 adversarial agent.

Generates concrete attack hypotheses for oracle manipulation vectors.
Covers:
  - Single-block spot price manipulation (getReserves, slot0, getPrice)
  - Stale Chainlink price exploitation
  - TWAP manipulation via sustained LP imbalance
  - Oracle-based collateral inflation (Cream-style)
"""

from __future__ import annotations

import logging

from zeropath.adversarial.base import BaseAdversarialAgent
from zeropath.adversarial.models import AttackClass, AttackHypothesis, ConditionType
from zeropath.invariants.models import (
    Invariant,
    InvariantType,
    OracleManipulationRisk,
    OracleType,
    ProtocolPattern,
)
from zeropath.models import ProtocolGraph

logger = logging.getLogger(__name__)

# Historical precedents per oracle attack pattern
_SPOT_PRICE_EXPLOITS = [
    "Cream Finance ($130M, 2021)",
    "Mango Markets ($117M, 2022)",
    "Inverse Finance ($15.6M, 2022)",
    "Venus Protocol ($200M, 2021)",
    "bZx ($350K, 2019)",
]
_STALE_ORACLE_EXPLOITS = [
    "Compound USDC freeze (2022)",
    "Synthetix sKRW infinite mint (2019)",
]
_TWAP_EXPLOITS = [
    "Euler Finance ($197M, 2023)",
    "Platypus Finance ($8.5M, 2023)",
]


class OracleManipulatorAgent(BaseAdversarialAgent):
    """Generates oracle manipulation attack hypotheses."""

    name = "OracleManipulatorAgent"
    attack_class = AttackClass.ORACLE_MANIPULATION
    relevant_invariant_types = [
        InvariantType.ORACLE_MANIPULATION,
        InvariantType.COLLATERALIZATION,
        InvariantType.VALUE_CONSERVATION,
        InvariantType.FLASH_LOAN_SAFETY,
    ]

    def analyse_invariant(
        self,
        invariant: Invariant,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[AttackHypothesis]:
        hypotheses: list[AttackHypothesis] = []

        for dep in invariant.oracle_dependencies:
            if dep.manipulation_risk == OracleManipulationRisk.HIGH:
                hypotheses.append(self._spot_price_attack(invariant, dep, pattern))
                if pattern.has_flash_loan or pattern.borrow_functions:
                    hypotheses.append(
                        self._flash_loan_oracle_attack(invariant, dep, pattern)
                    )
            elif dep.oracle_type == OracleType.CHAINLINK:
                hypotheses.append(self._stale_chainlink_attack(invariant, dep))
            elif dep.manipulation_risk == OracleManipulationRisk.MEDIUM:
                hypotheses.append(self._twap_manipulation_attack(invariant, dep))

        # If no oracle_dependencies on the invariant but the pattern has oracle vars
        if not invariant.oracle_dependencies and pattern.has_oracle:
            hypotheses.append(self._generic_oracle_attack(invariant, pattern))

        return hypotheses

    # ------------------------------------------------------------------
    # Hypothesis builders
    # ------------------------------------------------------------------

    def _spot_price_attack(self, invariant, dep, pattern) -> AttackHypothesis:
        contract = dep.contract_name
        fn = dep.function_name
        oracle = dep.oracle_contract

        steps = [
            self._step(1, "Acquire large flash loan from Aave/Balancer",
                       "Fund the price manipulation without capital requirement",
                       target_contract="AaveV3", target_function="flashLoan"),
            self._step(2, f"Swap borrowed funds into the {oracle} pool to skew reserves",
                       "Drive spot price up (or down) within the same block",
                       target_contract=oracle, target_function=dep.read_function),
            self._step(3, f"Call {fn} on {contract} while oracle reports manipulated price",
                       "Exploit the distorted price for profitable action",
                       target_contract=contract, target_function=fn),
            self._step(4, "Swap back to restore pool reserves",
                       "Minimise flash loan repayment cost",
                       target_contract=oracle),
            self._step(5, "Repay flash loan principal + fee",
                       "Close the atomic transaction with profit remaining",
                       target_contract="AaveV3", target_function="repay"),
        ]
        preconditions = [
            self._precondition(ConditionType.ORACLE_READ_SINGLE_BLOCK,
                               f"{dep.read_function} reads spot price in the same block",
                               is_met=dep.is_single_block,
                               evidence=dep.evidence),
            self._precondition(ConditionType.FLASH_LOAN_AVAILABLE,
                               "Flash loan provider accessible on same chain",
                               is_met=True),
            self._precondition(ConditionType.EXTERNAL_CALL_BEFORE_UPDATE,
                               f"{fn} uses oracle price before updating internal state",
                               is_met=dep.used_in_state_changing_function,
                               evidence=dep.evidence),
        ]
        profit = self._profit(
            f"Borrow/withdraw at inflated price via {fn}, repay at true price",
            asset="ERC20/ETH",
            max_usd=None,
        )
        poc = f"""// Foundry PoC sketch
contract AttackPoC {{
    IFlashLoan aave = IFlashLoan(AAVE_V3);
    {contract} target = {contract}(TARGET);
    {oracle} pool = {oracle}(POOL);

    function executeOperation(address[] calldata assets, ...) external {{
        // Step 2: skew oracle
        pool.swap(assets[0], largeAmount, ...);
        // Step 3: exploit
        target.{fn}(...);
        // Step 4: restore
        pool.swap(assets[0], largeAmount, ...);
        // Step 5: approve repayment handled by AAVE callback
    }}
}}"""
        return self._make_hypothesis(
            invariant,
            title=f"Flash loan + spot oracle manipulation via {dep.read_function}() in {fn}()",
            attack_class=AttackClass.ORACLE_MANIPULATION,
            narrative=(
                f"The function `{fn}` in `{contract}` reads price from `{oracle}.{dep.read_function}()`, "
                f"which returns a single-block spot price.  An attacker flash-loans a large amount, "
                f"manipulates the pool reserves in the same transaction, calls `{fn}` at the "
                f"distorted price, then restores reserves and repays the loan — pocketing the difference."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.85,
            historical_protocols=_SPOT_PRICE_EXPLOITS,
            historical_loss=130_000_000,
            poc_sketch=poc,
            suggested_fix=(
                f"Replace `{dep.read_function}()` with a Chainlink oracle or a TWAP with "
                f"at least 30-minute window.  Never use `getReserves()` or `slot0()` as a "
                f"price source in state-changing functions."
            ),
        )

    def _flash_loan_oracle_attack(self, invariant, dep, pattern) -> AttackHypothesis:
        contract = dep.contract_name
        fn = dep.function_name
        borrow_fn = pattern.borrow_functions[0] if pattern.borrow_functions else "borrow"

        steps = [
            self._step(1, "Flash-loan maximum available liquidity",
                       "Need capital to both manipulate oracle and exploit borrow",
                       target_function="flashLoan"),
            self._step(2, f"Deposit flash-loaned assets as collateral via {pattern.deposit_functions[0] if pattern.deposit_functions else 'deposit'}()",
                       "Inflate collateral value before oracle manipulation",
                       target_contract=contract,
                       target_function=pattern.deposit_functions[0] if pattern.deposit_functions else "deposit"),
            self._step(3, f"Manipulate {dep.oracle_contract} spot price upward",
                       "Make collateral appear worth more than it is",
                       target_contract=dep.oracle_contract),
            self._step(4, f"Borrow maximum against inflated collateral via {borrow_fn}()",
                       "Extract value at manipulated price",
                       target_contract=contract, target_function=borrow_fn),
            self._step(5, "Allow oracle to normalise, abandon collateral",
                       "Collateral is now worth less than the loan — profitable if borrow > true collateral value",
                       target_contract=contract),
            self._step(6, "Repay flash loan",
                       "Close atomic transaction",
                       target_function="repay"),
        ]
        preconditions = [
            self._precondition(ConditionType.ORACLE_READ_SINGLE_BLOCK,
                               "Borrow function reads manipulable spot price",
                               is_met=dep.is_single_block),
            self._precondition(ConditionType.FLASH_LOAN_AVAILABLE,
                               "Flash loan large enough to move oracle significantly",
                               is_met=True),
        ]
        profit = self._profit(
            "Borrow exceeds true collateral value; attacker keeps the difference",
            asset="ERC20",
            scales_with_tvl=True,
        )
        return self._make_hypothesis(
            invariant,
            title=f"Collateral inflation via oracle manipulation before {borrow_fn}()",
            attack_class=AttackClass.FLASH_LOAN,
            narrative=(
                f"Attacker flash-loans funds, deposits as collateral, manipulates the oracle "
                f"used by `{borrow_fn}` to inflate apparent collateral value, borrows the "
                f"maximum, then abandons the collateral.  The protocol is left with bad debt."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.80,
            historical_protocols=_SPOT_PRICE_EXPLOITS[:3],
            historical_loss=117_000_000,
            suggested_fix=(
                "Separate oracle reads from collateral valuation; use Chainlink for "
                "all collateral pricing; add per-block borrow limits."
            ),
        )

    def _stale_chainlink_attack(self, invariant, dep) -> AttackHypothesis:
        contract = dep.contract_name
        fn = dep.function_name

        steps = [
            self._step(1, "Monitor Chainlink heartbeat for staleness",
                       "Chainlink rounds have a 1-hour (or longer) heartbeat; during volatility "
                       "the last answer may be stale"),
            self._step(2, f"Wait for or trigger market conditions where true price diverges from stale Chainlink answer",
                       "Stale price creates arbitrage window"),
            self._step(3, f"Call {fn} on {contract} while oracle is stale",
                       "Borrow, withdraw, or liquidate at favourable (wrong) price",
                       target_contract=contract, target_function=fn),
            self._step(4, "Close position once oracle updates",
                       "Lock in profit from price discrepancy"),
        ]
        preconditions = [
            self._precondition(ConditionType.ORACLE_READ_SINGLE_BLOCK,
                               "No freshness check (updatedAt + heartbeat > block.timestamp)",
                               is_met=dep.used_in_state_changing_function,
                               evidence="Chainlink latestAnswer() used without staleness check"),
            self._precondition(ConditionType.CUSTOM,
                               "Token price is volatile enough to diverge meaningfully in one heartbeat",
                               is_met=None),
        ]
        profit = self._profit(
            "Extract value at stale price before oracle refreshes",
            asset="ERC20",
        )
        return self._make_hypothesis(
            invariant,
            title=f"Stale Chainlink price exploitation in {fn}()",
            attack_class=AttackClass.ORACLE_MANIPULATION,
            narrative=(
                f"`{contract}.{fn}` uses Chainlink `latestAnswer()` or `latestRoundData()` without "
                f"verifying the `updatedAt` timestamp.  During high volatility or Chainlink "
                f"downtime, the stale price can differ materially from market price, enabling "
                f"profitable liquidations or borrows."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.55,
            historical_protocols=_STALE_ORACLE_EXPLOITS,
            historical_loss=None,
            suggested_fix=(
                "Add: `require(block.timestamp - updatedAt <= MAX_ORACLE_DELAY, 'stale oracle');` "
                "after every `latestRoundData()` call.  Use `answeredInRound >= roundId` to detect "
                "incomplete rounds."
            ),
        )

    def _twap_manipulation_attack(self, invariant, dep) -> AttackHypothesis:
        contract = dep.contract_name
        fn = dep.function_name

        steps = [
            self._step(1, "Accumulate capital over multiple blocks to sustain price imbalance",
                       "TWAP requires sustained pressure — not achievable atomically"),
            self._step(2, "Buy/sell aggressively in the oracle pool over TWAP window duration",
                       "Push time-weighted average price in desired direction",
                       target_contract=dep.oracle_contract),
            self._step(3, f"Call {fn} on {contract} at end of TWAP window",
                       "Exploit the manipulated average price",
                       target_contract=contract, target_function=fn),
            self._step(4, "Unwind position in oracle pool",
                       "Recover capital used for manipulation"),
        ]
        preconditions = [
            self._precondition(ConditionType.CUSTOM,
                               "TWAP window is short enough (<= 10 min) to be economically feasible to manipulate",
                               is_met=dep.manipulation_risk == OracleManipulationRisk.MEDIUM),
            self._precondition(ConditionType.CUSTOM,
                               "Attacker has sufficient capital to sustain imbalance",
                               is_met=None),
        ]
        profit = self._profit("Borrow/withdraw at manipulated TWAP price", asset="ERC20")
        return self._make_hypothesis(
            invariant,
            title=f"Short TWAP oracle manipulation via sustained pool imbalance in {fn}()",
            attack_class=AttackClass.ORACLE_MANIPULATION,
            narrative=(
                f"`{fn}` uses a TWAP oracle from `{dep.oracle_contract}` with a short window.  "
                f"A well-capitalised attacker can sustain a price imbalance over the entire TWAP "
                f"window at acceptable cost, achieving a manipulated average price."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.45,
            historical_protocols=_TWAP_EXPLOITS,
            suggested_fix=(
                "Extend TWAP window to >= 30 minutes.  Consider Chainlink as primary "
                "and TWAP as a secondary sanity check."
            ),
        )

    def _generic_oracle_attack(self, invariant, pattern) -> AttackHypothesis:
        contract = (invariant.contracts_involved or ["Unknown"])[0]
        fn = (invariant.functions_involved or ["unknownFunction"])[0]
        oracle_var = (pattern.oracle_vars or ["oracle"])[0]

        steps = [
            self._step(1, f"Identify the oracle source used by {oracle_var} in {contract}",
                       "Determine if it's a spot price, TWAP, or Chainlink feed"),
            self._step(2, f"Manipulate or wait for oracle to report a favourable price",
                       "Method depends on oracle type (flash loan for spot, time for TWAP)"),
            self._step(3, f"Call {fn} while oracle price is distorted",
                       "Exploit the protocol at the manipulated price",
                       target_contract=contract, target_function=fn),
        ]
        preconditions = [
            self._precondition(ConditionType.ORACLE_READ_SINGLE_BLOCK,
                               f"{oracle_var} may read a manipulable price source",
                               is_met=None),
        ]
        profit = self._profit("Profit depends on oracle type and function exploited", asset="ERC20")
        return self._make_hypothesis(
            invariant,
            title=f"Potential oracle manipulation via {oracle_var} in {fn}()",
            attack_class=AttackClass.ORACLE_MANIPULATION,
            narrative=(
                f"The protocol uses `{oracle_var}` as a price source.  If this is a spot price "
                f"oracle, it can be manipulated within a single transaction.  Manual review of "
                f"the oracle implementation is required to confirm exploitability."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.40,
            suggested_fix="Audit oracle source; prefer Chainlink with staleness checks.",
        )
