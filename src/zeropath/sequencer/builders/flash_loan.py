"""
FlashLoanSequenceBuilder — Phase 4.

Converts FLASH_LOAN and ORACLE_MANIPULATION (flash-loan-funded) hypotheses
into concrete transaction sequences.

Pattern:
  1. Request flash loan (Aave V3 flashLoan)
  2. executeOperation callback: execute attack steps
  3. Repay loan + fee
  4. Assert profit
"""

from __future__ import annotations

from zeropath.adversarial.models import AttackClass, AttackHypothesis, ConditionType
from zeropath.models import ProtocolGraph
from zeropath.sequencer.base import (
    FLASH_LOAN_PROVIDERS,
    KNOWN_TOKENS,
    BaseSequenceBuilder,
)
from zeropath.sequencer.models import (
    AttackContext,
    CallerType,
    ProfitEstimate,
    TxCall,
)

_AAVE_V3 = FLASH_LOAN_PROVIDERS["aave_v3"]
_WETH = KNOWN_TOKENS["weth"]


class FlashLoanSequenceBuilder(BaseSequenceBuilder):
    """Builds transaction sequences for flash loan attacks."""

    attack_class = AttackClass.FLASH_LOAN

    def _build_calls(
        self,
        hypothesis: AttackHypothesis,
        graph: ProtocolGraph,
    ) -> list[TxCall]:
        target_contract = (hypothesis.contracts_involved or ["TargetContract"])[0]
        target_fn = (hypothesis.functions_involved or ["borrow"])[0]

        # Determine which flash loan provider to use
        provider_addr = _AAVE_V3  # default Aave V3

        # Build sequence around the hypothesis exploit_steps
        calls: list[TxCall] = []

        # Step 1 — setup approval if needed
        calls.append(self._call(
            step=1,
            description="Approve Aave V3 to pull repayment (set max allowance)",
            target=f"IERC20(WETH)",
            sig="approve(address,uint256)",
            calldata=f"address({provider_addr}), type(uint256).max",
            caller=CallerType.ATTACKER_CONTRACT,
            post=["/* approval set */"],
            gas=50_000,
        ))

        # Step 2 — initiate flash loan (triggers executeOperation callback)
        calls.append(self._call(
            step=2,
            description="Request flash loan from Aave V3 — triggers executeOperation()",
            target=f"IPool({provider_addr})",
            sig="flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)",
            calldata=(
                "address(this), assets, amounts, modes, address(this), params, 0"
            ),
            caller=CallerType.ATTACKER_CONTRACT,
            pre=[f"uint256 balBefore = IERC20(WETH).balanceOf(address(this));"],
            post=["/* flash loan repaid; check profit below */"],
            gas=500_000,
        ))

        # Step 3 — inside executeOperation: the actual attack
        # Map hypothesis exploit_steps (3+) to inner calls
        for i, step in enumerate(hypothesis.exploit_steps[1:-1], start=3):
            inner_target = step.target_contract or target_contract
            inner_fn = step.target_function or target_fn
            calls.append(self._call(
                step=i,
                description=f"[executeOperation] {step.action}",
                target=f"I{inner_target}(/* {inner_target} address */)",
                sig=f"{inner_fn}(/* TODO: params */)",
                calldata="/* TODO: fill args */",
                caller=CallerType.ATTACKER_CONTRACT,
                gas=200_000,
            ))

        # Final step — profit assertion
        calls.append(self._call(
            step=len(calls) + 1,
            description="Assert attacker profit after flash loan repaid",
            target="address(this)",
            sig=None,
            calldata="",
            caller=CallerType.ATTACKER_CONTRACT,
            post=[
                "uint256 balAfter = IERC20(WETH).balanceOf(address(this));",
                "assertGt(balAfter, balBefore, 'Attack not profitable');",
            ],
            gas=21_000,
        ))

        return calls

    def _build_context(
        self,
        hypothesis: AttackHypothesis,
        graph: ProtocolGraph,
    ) -> AttackContext:
        ctx = super()._build_context(hypothesis, graph)
        ctx.requires_attacker_contract = True
        ctx.flash_loan_provider = _AAVE_V3
        ctx.attacker_token_balances = {"WETH": "0"}  # funded by flash loan
        ctx.requires_single_block = True
        ctx.contract_addresses["WETH"] = _WETH
        ctx.contract_addresses["AaveV3"] = _AAVE_V3
        return ctx

    def _build_profit_estimate(self, hypothesis: AttackHypothesis) -> ProfitEstimate | None:
        asset = hypothesis.profit_mechanism.asset if hypothesis.profit_mechanism else "WETH"
        return ProfitEstimate(
            asset=asset,
            min_profit_expression="1e15",  # 0.001 ETH minimum to be worthwhile
            max_profit_expression="IERC20(TARGET_TOKEN).balanceOf(address(TARGET))",
            cost_expression="(flashAmount * 9) / 10000",  # Aave 0.09% fee
            scales_with_tvl=True,
            notes=f"Profit = extracted value - flash loan fee (0.09% of flashAmount). {hypothesis.profit_mechanism.description if hypothesis.profit_mechanism else ''}",
        )
