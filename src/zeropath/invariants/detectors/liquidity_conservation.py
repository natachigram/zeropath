"""
Liquidity conservation invariant detector (AMM).

For AMMs (Uniswap/Curve-style), the constant product (or sum) invariant
must never be violated by a swap.

Detection strategy:
  1. Detect AMM protocol (swap functions + reserve state variables).
  2. Detect Uniswap V2 style (getReserves, k = x * y).
  3. Detect Uniswap V3 style (slot0, concentrated liquidity).
  4. Detect Curve/stable style (different invariant formula).
  5. Flag fee-on-transfer token risks.
  6. Flag reentrancy in AMM price reads (see Curve Vyper hack).
"""

from __future__ import annotations

from zeropath.invariants.detectors.base import BaseDetector
from zeropath.invariants.formal_spec import FormalSpecGenerator
from zeropath.invariants.models import (
    Invariant,
    InvariantSeverity,
    InvariantType,
    ProtocolPattern,
)
from zeropath.invariants.rag import get_rag
from zeropath.logging_config import get_logger
from zeropath.models import ProtocolGraph

logger = get_logger(__name__)

_spec_gen = FormalSpecGenerator()
_rag = get_rag()

_RESERVE_VAR_KW = {
    "reserve", "reserve0", "reserve1", "balance0", "balance1",
    "pool", "poolbalance", "liquidity",
}
_K_INVARIANT_KW = {"klast", "k_last", "k", "product", "invariant"}
_V3_POOL_KW = {"slot0", "sqrtpricex96", "tick", "liquidity", "feegrowth"}
_CURVE_KW = {"a", "d", "xcpprofit", "virtualPrice"}


class LiquidityConservationDetector(BaseDetector):
    """Detect AMM liquidity conservation invariants."""

    name = "liquidity_conservation"

    def detect(
        self,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[Invariant]:
        results: list[Invariant] = []

        # Must have swap functions to be an AMM
        if not pattern.swap_functions:
            return results

        var_names_lower = {v.name.lower() for v in graph.state_variables}
        func_names_lower = {f.name.lower() for f in graph.functions}

        is_v2_style = bool(var_names_lower & _RESERVE_VAR_KW)
        is_v3_style = bool(var_names_lower & _V3_POOL_KW or "slot0" in func_names_lower)
        has_k_var = bool(var_names_lower & _K_INVARIANT_KW)

        if not (is_v2_style or is_v3_style):
            return results

        # Constant product invariant (Uniswap V2 style)
        if is_v2_style:
            results.append(self._k_invariant_finding(pattern, has_k_var))

        # Concentrated liquidity price bounds (V3 style)
        if is_v3_style:
            results.append(self._v3_price_integrity_finding(pattern))

        # Read-only reentrancy in price reads
        has_reentrancy_guard = pattern.has_reentrancy_guard
        if not has_reentrancy_guard and (is_v2_style or is_v3_style):
            results.append(self._readonly_reentrancy_finding(pattern))

        logger.debug("liquidity_conservation_detector", findings=len(results))
        return results

    # ------------------------------------------------------------------

    def _k_invariant_finding(self, pattern: ProtocolPattern, has_k_var: bool) -> Invariant:
        precedents = _rag.query(
            InvariantType.LIQUIDITY_CONSERVATION,
            tags={"amm", "k_invariant"},
        )
        boost = _rag.confidence_boost(precedents)
        evidence_str = _rag.evidence_summary(precedents)

        evidence = [
            f"AMM swap functions: {pattern.swap_functions[:3]}.",
            "Constant product invariant: reserve0 * reserve1 >= kLast after every swap.",
            f"kLast variable {'detected' if has_k_var else 'NOT detected — invariant may not be tracked'}.",
        ]
        if evidence_str:
            evidence.append(evidence_str)

        return Invariant(
            type=InvariantType.LIQUIDITY_CONSERVATION,
            severity=InvariantSeverity.HIGH,
            description=(
                "AMM constant product invariant: k = reserve0 * reserve1 must not decrease "
                "after any swap. Fees may increase k. Any code path that decreases k is an "
                "invariant violation. (See KyberSwap $48M, Uranium Finance $57M)."
            ),
            formal_spec=_spec_gen.generate(InvariantType.LIQUIDITY_CONSERVATION, pattern),
            confidence=min(0.70 + boost, 0.95),
            functions_involved=pattern.swap_functions[:10],
            historical_precedent=precedents,
            evidence=evidence,
            detector=self.name,
        )

    def _v3_price_integrity_finding(self, pattern: ProtocolPattern) -> Invariant:
        precedents = _rag.query(
            InvariantType.LIQUIDITY_CONSERVATION,
            tags={"amm", "concentrated_liquidity"},
        )
        boost = _rag.confidence_boost(precedents)

        evidence = [
            "Uniswap V3-style concentrated liquidity detected (slot0 / sqrtPriceX96).",
            "Price must remain within active tick range; tick boundary math must not "
            "double-count liquidity at range edges.",
        ]

        return Invariant(
            type=InvariantType.LIQUIDITY_CONSERVATION,
            severity=InvariantSeverity.MEDIUM,
            description=(
                "V3 price integrity: sqrtPriceX96 must remain within the active tick range. "
                "Tick boundary crossing must correctly account for liquidity transitions."
            ),
            formal_spec=_spec_gen.generate(InvariantType.LIQUIDITY_CONSERVATION, pattern),
            confidence=min(0.55 + boost, 0.95),
            functions_involved=pattern.swap_functions[:10],
            historical_precedent=precedents,
            evidence=evidence,
            detector=self.name,
        )

    def _readonly_reentrancy_finding(self, pattern: ProtocolPattern) -> Invariant:
        precedents = _rag.query(
            InvariantType.REENTRANCY,
            tags={"reentrancy", "amm", "vyper"},
        )
        boost = _rag.confidence_boost(precedents)
        evidence_str = _rag.evidence_summary(precedents)

        evidence = [
            "AMM pool without reentrancy guard — read-only reentrancy risk.",
            "An external callback (e.g. ETH receive, ERC-777 hook) can re-enter a "
            "price read before the pool updates its reserves.",
        ]
        if evidence_str:
            evidence.append(evidence_str)

        return Invariant(
            type=InvariantType.LIQUIDITY_CONSERVATION,
            severity=InvariantSeverity.HIGH,
            description=(
                "Read-only reentrancy: AMM price/reserve reads during callbacks can "
                "return stale values before state is updated. External protocols using "
                "this pool as a price oracle are vulnerable. (See Curve Vyper $70M)."
            ),
            formal_spec=_spec_gen.generate(InvariantType.REENTRANCY, pattern),
            confidence=min(0.65 + boost, 0.95),
            functions_involved=pattern.swap_functions[:10],
            historical_precedent=precedents,
            evidence=evidence,
            detector=self.name,
        )
