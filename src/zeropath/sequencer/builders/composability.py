"""
Cross-protocol composability sequence builder — Phase 4.

Spec (phases.md, PHASE 4 critical additions, "Cross-protocol composability"):
    "Attacks that span multiple protocols in a single transaction are the
     most profitable. The sequence generator must support multi-protocol
     call chains: fetch price from protocol A → manipulate via protocol B
     → exploit protocol C → repay."

This builder produces a four-leg chain when the hypothesis pulls in at least
two distinct external protocols:

  1. **Read** — query a price/state oracle on protocol A (no-op for
     simulation, but anchors the snapshot for Phase 5).
  2. **Borrow** — flash-loan from protocol B (Aave V3, Balancer).
  3. **Manipulate** — interact with protocol C to skew the shared state
     (AMM swap, oracle update, governance vote).
  4. **Exploit** — call the vulnerable function on the target protocol with
     the manipulated state still in flight.
  5. **Repay** — return flash-loaned funds plus fee.

Each TxCall carries concrete ``params`` + ``param_types`` so the ABI encoder
can populate ``calldata_hex`` directly for Phase 5 execution.
"""

from __future__ import annotations

from typing import Optional

from zeropath.adversarial.models import (
    AttackClass,
    AttackHypothesis,
    ConditionType,
)
from zeropath.models import ProtocolGraph
from zeropath.sequencer.base import (
    FLASH_LOAN_PROVIDERS,
    KNOWN_TOKENS,
    BaseSequenceBuilder,
)
from zeropath.sequencer.models import (
    AttackContext,
    CallerType,
    CallEncoding,
    ProfitEstimate,
    TxCall,
)

_AAVE_V3 = FLASH_LOAN_PROVIDERS["aave_v3"]
_WETH = KNOWN_TOKENS["weth"]
_USDC = KNOWN_TOKENS["usdc"]


def _placeholder_addr(label: str) -> str:
    """
    Deterministic 20-byte placeholder so Phase 4 still emits a valid hex
    address when the live address can't be resolved from the graph.
    """
    raw = (label + "_____________________________")[:20].encode("ascii", errors="replace")
    return "0x" + raw.hex()


def _distinct_protocols(hypothesis: AttackHypothesis) -> list[str]:
    """Collect distinct external protocol identifiers from the hypothesis."""
    seen: list[str] = []
    for contract in hypothesis.contracts_involved or []:
        if contract and contract not in seen:
            seen.append(contract)
    # Many composability hypotheses reference protocols by name in the
    # narrative even when contracts_involved is sparse.
    for kw in ("Aave", "Compound", "Uniswap", "Balancer", "Curve", "Lido", "MakerDAO", "Yearn"):
        if kw.lower() in (hypothesis.attack_narrative or "").lower() and kw not in seen:
            seen.append(kw)
    return seen


class ComposabilitySequenceBuilder(BaseSequenceBuilder):
    """
    Multi-protocol composability attack sequencer.

    Activates on AttackClass.COMPOSABILITY hypotheses that touch ≥2 external
    protocols. For single-protocol hypotheses the orchestrator should fall
    back to a class-specific builder (oracle, flash loan, etc.).
    """

    attack_class = AttackClass.COMPOSABILITY

    def _build_calls(
        self,
        hypothesis: AttackHypothesis,
        graph: ProtocolGraph,
    ) -> list[TxCall]:
        protocols = _distinct_protocols(hypothesis)
        if len(protocols) < 2:
            # Caller will skip; this builder only handles true multi-protocol.
            return []

        source_protocol = protocols[0]
        target_protocol = protocols[-1]
        manipulation_protocol = protocols[1] if len(protocols) >= 2 else target_protocol

        target_fn = (hypothesis.functions_involved or ["exploit"])[0]
        provider = self._select_flash_provider(hypothesis)

        # --- 1. READ ----------------------------------------------------
        oracle = _placeholder_addr(f"{source_protocol}_oracle")
        read = self._call(
            step=1,
            description=(
                f"[READ] Query {source_protocol} state — captures the pre-attack "
                "price/oracle reading for assertion + telemetry."
            ),
            target=f"I{source_protocol}Oracle({oracle})",
            sig="getReserves()",
            calldata="/* no args */",
            caller=CallerType.ATTACKER_CONTRACT,
            encoding=CallEncoding.STATIC_CALL,
            pre=[
                "// Anchor the snapshot — Phase 5 fork must produce the same reading.",
            ],
            gas=8_000,
        )
        read.target_address = oracle
        read.function_signature = "getReserves()"
        read.params = []
        read.param_types = []

        # --- 2. BORROW (flash loan from provider) -----------------------
        flash_amount = 100 * 10**18  # 100 ETH
        flash_token = _WETH
        borrow = self._call(
            step=2,
            description=(
                f"[BORROW] Flash-loan {flash_amount // 10**18} WETH from "
                f"{self._provider_name(provider)} ({provider}) — funds the manipulation."
            ),
            target=f"IPool({provider})",
            sig="flashLoanSimple(address,address,uint256,bytes,uint16)",
            calldata="address(this), WETH, flashAmount, '', 0",
            value="0",
            caller=CallerType.ATTACKER_CONTRACT,
            pre=[
                "uint256 attackerBalBefore = IERC20(WETH).balanceOf(address(this));",
            ],
            gas=600_000,
        )
        borrow.target_address = provider
        borrow.function_signature = "flashLoanSimple(address,address,uint256,bytes,uint16)"
        borrow.params = [
            "0x0000000000000000000000000000000000000000",   # filled by Phase 5 w/ attacker address
            flash_token,
            flash_amount,
            b"",
            0,
        ]
        borrow.param_types = ["address", "address", "uint256", "bytes", "uint16"]

        # --- 3. MANIPULATE (AMM swap on a 2nd protocol) -----------------
        manip_pool = _placeholder_addr(f"{manipulation_protocol}_pool")
        manipulate = self._call(
            step=3,
            description=(
                f"[MANIPULATE] Swap on {manipulation_protocol} to skew the "
                f"shared price/state read by {target_protocol}."
            ),
            target=f"I{manipulation_protocol}({manip_pool})",
            sig="swap(uint256,uint256,address,bytes)",
            calldata="amount0Out, amount1Out, address(this), ''",
            caller=CallerType.ATTACKER_CONTRACT,
            post=[
                "// Reserve ratio is now skewed; the read in step 4 will see this.",
            ],
            gas=180_000,
        )
        manipulate.target_address = manip_pool
        manipulate.function_signature = "swap(uint256,uint256,address,bytes)"
        manipulate.params = [
            flash_amount,
            0,
            "0x0000000000000000000000000000000000000000",
            b"",
        ]
        manipulate.param_types = ["uint256", "uint256", "address", "bytes"]

        # --- 4. EXPLOIT (call vulnerable function on target protocol) ---
        target_addr = _placeholder_addr(f"{target_protocol}_target")
        exploit = self._call(
            step=4,
            description=(
                f"[EXPLOIT] Call {target_protocol}.{target_fn}() while shared "
                f"state is mid-manipulation. Composability boundary crossed."
            ),
            target=f"I{target_protocol}({target_addr})",
            sig=f"{target_fn}(uint256)",
            calldata="exploitAmount",
            caller=CallerType.ATTACKER_CONTRACT,
            post=[
                "uint256 attackerBalAfter = IERC20(WETH).balanceOf(address(this));",
                "// Composability profit asserted at step 5 after repay.",
            ],
            gas=400_000,
        )
        exploit.target_address = target_addr
        exploit.function_signature = f"{target_fn}(uint256)"
        exploit.params = [flash_amount]  # exploit amount linked to flash size
        exploit.param_types = ["uint256"]

        # --- 5. REPAY ---------------------------------------------------
        fee = flash_amount * 9 // 10_000  # Aave 0.09%
        repay = self._call(
            step=5,
            description=(
                f"[REPAY] Repay flash loan principal + 0.09% fee "
                f"({fee // 10**15} mwei) back to {self._provider_name(provider)}."
            ),
            target=f"IERC20({flash_token})",
            sig="transfer(address,uint256)",
            calldata=f"address({provider}), flashAmount + flashFee",
            caller=CallerType.ATTACKER_CONTRACT,
            post=[
                "assertGt(attackerBalAfter, attackerBalBefore, "
                "'Composability attack not profitable');",
            ],
            gas=65_000,
        )
        repay.target_address = flash_token
        repay.function_signature = "transfer(address,uint256)"
        repay.params = [provider, flash_amount + fee]
        repay.param_types = ["address", "uint256"]

        return [read, borrow, manipulate, exploit, repay]

    def _build_context(
        self,
        hypothesis: AttackHypothesis,
        graph: ProtocolGraph,
    ) -> AttackContext:
        ctx = super()._build_context(hypothesis, graph)
        ctx.requires_attacker_contract = True
        ctx.flash_loan_provider = self._select_flash_provider(hypothesis)
        ctx.requires_single_block = True
        ctx.contract_addresses["WETH"] = _WETH
        ctx.contract_addresses["AaveV3"] = _AAVE_V3
        # Persist the list of protocols at the orchestrator layer too.
        return ctx

    def _build_profit_estimate(
        self, hypothesis: AttackHypothesis
    ) -> Optional[ProfitEstimate]:
        return ProfitEstimate(
            asset="WETH",
            min_profit_expression="1e16",   # 0.01 WETH minimum
            max_profit_expression="IERC20(TARGET_TOKEN).balanceOf(address(TARGET))",
            cost_expression="(flashAmount * 9) / 10000",
            scales_with_tvl=True,
            notes=(
                "Composability profit = extracted value at target protocol "
                "− flash fee − gas. Scales with the *smaller* of: target TVL "
                "or AMM depth used for manipulation."
            ),
        )

    @staticmethod
    def _select_flash_provider(hypothesis: AttackHypothesis) -> str:
        """Pick a flash provider based on declared preconditions."""
        for p in hypothesis.preconditions:
            if p.condition_type != ConditionType.FLASH_LOAN_AVAILABLE:
                continue
            ev = (p.evidence or "").lower()
            if "balancer" in ev:
                return FLASH_LOAN_PROVIDERS["balancer"]
            if "uniswap" in ev:
                return FLASH_LOAN_PROVIDERS["uniswap_v3"]
        return _AAVE_V3

    @staticmethod
    def _provider_name(addr: str) -> str:
        for name, a in FLASH_LOAN_PROVIDERS.items():
            if a.lower() == addr.lower():
                return name
        return "unknown"
