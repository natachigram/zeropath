"""
ReentrancySequenceBuilder — Phase 4.

Converts REENTRANCY hypotheses into transaction sequences.

Handles:
  - Classic reentrancy (receive/fallback re-entry)
  - Cross-function reentrancy (re-enter different function)
  - Read-only reentrancy (AMM callback → lending oracle)
  - Delegatecall reentrancy
"""

from __future__ import annotations

from zeropath.adversarial.models import AttackClass, AttackHypothesis
from zeropath.models import ProtocolGraph
from zeropath.sequencer.base import BaseSequenceBuilder
from zeropath.sequencer.models import (
    AttackContext,
    CallerType,
    ProfitEstimate,
    TxCall,
)


class ReentrancySequenceBuilder(BaseSequenceBuilder):
    """Builds transaction sequences for reentrancy attacks."""

    attack_class = AttackClass.REENTRANCY

    def _build_calls(
        self,
        hypothesis: AttackHypothesis,
        graph: ProtocolGraph,
    ) -> list[TxCall]:
        target_contract = (hypothesis.contracts_involved or ["Target"])[0]
        target_fn = (hypothesis.functions_involved or ["withdraw"])[0]
        title_lower = hypothesis.title.lower()

        if "cross-function" in title_lower:
            return self._cross_function_sequence(hypothesis, target_contract, target_fn)
        if "read-only" in title_lower or "amm" in title_lower:
            return self._read_only_sequence(hypothesis, target_contract, target_fn)
        if "delegatecall" in title_lower:
            return self._delegatecall_sequence(hypothesis, target_contract, target_fn)
        return self._classic_sequence(hypothesis, target_contract, target_fn)

    def _classic_sequence(self, hypothesis, target_contract, target_fn) -> list[TxCall]:
        return [
            self._call(
                step=1,
                description=f"Deploy ReentrancyAttacker contract targeting {target_contract}.{target_fn}()",
                target="/* deploy new ReentrancyAttacker() */",
                sig=None,
                caller=CallerType.ATTACKER_EOA,
                pre=["uint256 victimBalBefore = address(TARGET).balance;"],
                gas=500_000,
            ),
            self._call(
                step=2,
                description=f"Call attacker.attack() — seeds with small ETH deposit to {target_contract}",
                target="address(attackerContract)",
                sig="attack()",
                calldata="",
                value="1 ether",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "// receive() triggers: re-enters withdraw() before balance decremented",
                    "// Each re-entry drains another unit of ETH from target",
                ],
                gas=300_000,
            ),
            self._call(
                step=3,
                description="Collect drained ETH from attacker contract",
                target="address(attackerContract)",
                sig="collectProfit(address)",
                calldata="payable(msg.sender)",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "uint256 attackerBal = address(attacker).balance;",
                    "assertGt(attackerBal, 1 ether, 'Reentrancy did not drain funds');",
                ],
                gas=50_000,
            ),
        ]

    def _cross_function_sequence(self, hypothesis, target_contract, target_fn) -> list[TxCall]:
        fn_list = hypothesis.functions_involved
        fn1 = fn_list[0] if fn_list else target_fn
        fn2 = fn_list[1] if len(fn_list) > 1 else "mint"

        return [
            self._call(
                step=1,
                description=f"Deploy CrossFunctionAttacker targeting {target_contract}",
                target="/* deploy new CrossFunctionAttacker() */",
                sig=None,
                caller=CallerType.ATTACKER_EOA,
                gas=600_000,
            ),
            self._call(
                step=2,
                description=f"Call {fn1}() — triggers external call; callback re-enters {fn2}()",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig=f"{fn1}(/* params */)",
                calldata="/* TODO: params */",
                caller=CallerType.ATTACKER_CONTRACT,
                post=[
                    f"// Inside callback: attacker calls target.{fn2}()",
                    "// target.{fn2} sees stale state (not yet updated by {fn1})",
                    "// Results in double-spend or accounting inconsistency",
                ],
                gas=400_000,
            ),
            self._call(
                step=3,
                description="Verify accounting inconsistency / extract double-spent value",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig="withdraw(uint256)",
                calldata="type(uint256).max",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "// Withdrawal should exceed deposited amount if cross-function re-entry succeeded",
                    "assertGt(address(this).balance, 0, 'No profit from cross-function reentry');",
                ],
                gas=100_000,
            ),
        ]

    def _read_only_sequence(self, hypothesis, target_contract, target_fn) -> list[TxCall]:
        return [
            self._call(
                step=1,
                description="Deploy ReadOnlyReentrancyAttacker (implements AMM callback + lending borrow)",
                target="/* deploy new ReadOnlyReentrancyAttacker() */",
                sig=None,
                caller=CallerType.ATTACKER_EOA,
                gas=700_000,
            ),
            self._call(
                step=2,
                description="Initiate AMM swap — triggers callback BEFORE reserves update",
                target=f"I{target_contract}(/* AMM address */)",
                sig="swap(uint256,uint256,address,bytes)",
                calldata="0, amountOut, address(attackerContract), abi.encode('attack')",
                caller=CallerType.ATTACKER_CONTRACT,
                post=[
                    "// Inside uniswapV2Call/uniswapV3SwapCallback:",
                    "// Call lending protocol which reads STALE AMM reserves as oracle",
                    "// Borrow against inflated/deflated collateral price",
                ],
                gas=500_000,
            ),
            self._call(
                step=3,
                description="Collect borrowed funds — callback has already executed lending borrow",
                target="address(attackerContract)",
                sig="collectBorrowedFunds()",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "assertGt(IERC20(BORROWED_TOKEN).balanceOf(address(this)), 0, 'No borrow profit');",
                ],
                gas=80_000,
            ),
        ]

    def _delegatecall_sequence(self, hypothesis, target_contract, target_fn) -> list[TxCall]:
        return [
            self._call(
                step=1,
                description="Deploy MaliciousImplementation — contains drain logic in storage context",
                target="/* deploy new MaliciousImplementation() */",
                sig=None,
                caller=CallerType.ATTACKER_EOA,
                gas=500_000,
            ),
            self._call(
                step=2,
                description=f"Trigger {target_fn}() which delegatecalls to attacker's contract",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig=f"{target_fn}(address)",
                calldata="address(maliciousImpl)",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "// delegatecall executes attacker code in caller's storage context",
                    "// Can overwrite admin slot, balance slot, or drain ETH",
                ],
                gas=300_000,
            ),
            self._call(
                step=3,
                description="Withdraw drained funds from contract storage",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig="withdraw()",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "assertGt(address(this).balance, 0, 'Delegatecall context hijack failed');",
                ],
                gas=100_000,
            ),
        ]

    def _build_context(self, hypothesis, graph) -> AttackContext:
        ctx = super()._build_context(hypothesis, graph)
        ctx.requires_attacker_contract = True
        ctx.attacker_eth_balance = "10 ether"  # seed capital for initial deposit
        return ctx

    def _build_profit_estimate(self, hypothesis) -> ProfitEstimate | None:
        return ProfitEstimate(
            asset="ETH",
            min_profit_expression="address(TARGET).balance",
            max_profit_expression="address(TARGET).balance",
            cost_expression="1 ether",  # seed deposit
            scales_with_tvl=True,
            notes="Drain all ETH in target contract via recursive re-entry.",
        )
