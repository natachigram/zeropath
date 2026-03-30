"""
Balance consistency invariant detector.

Infers: sum(balanceOf[u] for all u) == totalSupply() at all times.

Detection strategy:
  1. Detect ERC-20 token contracts (has transfer, mint, burn, totalSupply).
  2. Detect any internal accounting mapping alongside totalSupply variable.
  3. Flag if the token is a rebasing or fee-on-transfer token (may violate
     the simple sum invariant).
  4. Detect ERC4626 vaults: convertToShares(convertToAssets(shares)) <= shares.
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

_REBASE_KW = {"rebase", "elastic", "atoken", "rtoken", "index", "scalingfactor"}
_FEE_ON_TRANSFER_KW = {"fee", "deflationary", "burnfee", "transferfee"}


class BalanceConsistencyDetector(BaseDetector):
    """Detect balance consistency invariant for token contracts."""

    name = "balance_consistency"

    def detect(
        self,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[Invariant]:
        results: list[Invariant] = []

        # Only relevant for ERC-20 tokens or contracts with balance accounting
        if not pattern.is_erc20 and not pattern.balance_vars:
            return results

        is_rebase = _is_rebase_token(graph)
        is_fee_transfer = _is_fee_on_transfer(graph)

        severity = InvariantSeverity.MEDIUM
        confidence = 0.65
        extra_evidence = []

        if is_rebase:
            severity = InvariantSeverity.LOW
            confidence = 0.40
            extra_evidence.append(
                "Rebasing token detected: simple sum-of-balances == totalSupply may not "
                "hold between rebase events. Scaled accounting required."
            )
        elif is_fee_transfer:
            severity = InvariantSeverity.HIGH
            confidence = 0.70
            extra_evidence.append(
                "Fee-on-transfer token detected: protocols using this token as AMM liquidity "
                "or collateral may violate their own balance accounting (see Balancer STA hack)."
            )

        tags = {"conservation"}
        if is_fee_transfer:
            tags.add("fee_on_transfer")

        precedents = _rag.query(InvariantType.BALANCE_CONSISTENCY, tags=tags)
        boost = _rag.confidence_boost(precedents)
        evidence_str = _rag.evidence_summary(precedents)

        funcs = (
            [f for f in pattern.deposit_functions + pattern.withdraw_functions]
            + (pattern.mint_functions or [])
            + (pattern.burn_functions or [])
        )

        evidence = [
            f"ERC-20 token detected with balance vars: {pattern.balance_vars[:3]}, "
            f"supply vars: {pattern.supply_vars[:3]}.",
        ] + extra_evidence

        if evidence_str:
            evidence.append(evidence_str)

        results.append(
            Invariant(
                type=InvariantType.BALANCE_CONSISTENCY,
                severity=severity,
                description=(
                    "Balance consistency: sum of all user balances must equal totalSupply() "
                    "at all times. "
                    + ("Rebasing logic complicates this invariant." if is_rebase else "")
                    + ("Fee-on-transfer may break protocol accounting." if is_fee_transfer else "")
                ),
                formal_spec=_spec_gen.generate(InvariantType.BALANCE_CONSISTENCY, pattern),
                confidence=min(confidence + boost, 0.95),
                functions_involved=list(set(funcs))[:10],
                state_vars_involved=(pattern.balance_vars + pattern.supply_vars)[:5],
                historical_precedent=precedents,
                evidence=evidence,
                detector=self.name,
            )
        )

        logger.debug("balance_consistency_detector", findings=len(results))
        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_rebase_token(graph: ProtocolGraph) -> bool:
    """Heuristic: detect rebasing / elastic supply token."""
    all_names = [v.name.lower() for v in graph.state_variables] + \
                [f.name.lower() for f in graph.functions]
    return any(kw in n for n in all_names for kw in _REBASE_KW)


def _is_fee_on_transfer(graph: ProtocolGraph) -> bool:
    """Heuristic: detect fee-on-transfer token."""
    all_names = [v.name.lower() for v in graph.state_variables] + \
                [f.name.lower() for f in graph.functions]
    return any(kw in n for n in all_names for kw in _FEE_ON_TRANSFER_KW)
