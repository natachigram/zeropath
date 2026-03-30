"""
Share accounting invariant detector.

Covers ERC-4626 vaults and any share-based accounting pattern.

Key invariants:
  1. convertToShares(convertToAssets(shares)) <= shares  (no inflation)
  2. Share price must never jump within a single transaction.
  3. First depositor cannot inflate share price to front-run others.
  4. Total shares * price_per_share == totalAssets() (approximately).

Detection strategy:
  1. Detect ERC-4626 vaults (converToShares, convertToAssets, previewDeposit).
  2. Detect share-based patterns (share_vars, deposit_functions).
  3. Check for virtual offset / dead shares protection against inflation attacks.
  4. Flag protocols missing dead shares protection as HIGH risk.
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

# Variable/function names that suggest inflation protection
_DEAD_SHARE_KW = {
    "offset", "deadshares", "virtualshares", "minshares",
    "initialshares", "burnedshares", "locked",
}
_VIRTUAL_ASSET_KW = {"virtualassets", "decimalsoffset", "offset", "virtual"}


class ShareAccountingDetector(BaseDetector):
    """Detect share accounting and ERC-4626 vault invariants."""

    name = "share_accounting"

    def detect(
        self,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[Invariant]:
        results: list[Invariant] = []

        is_vault = (
            pattern.is_erc4626
            or (pattern.share_vars and pattern.deposit_functions)
        )

        if not is_vault:
            return results

        has_inflation_protection = _has_inflation_protection(graph)
        is_erc4626 = pattern.is_erc4626

        # Share inflation attack (ERC-4626 specific)
        if is_erc4626 and not has_inflation_protection:
            results.append(self._share_inflation_finding(pattern))

        # General share accounting invariant
        results.append(self._share_round_trip_finding(pattern))

        logger.debug("share_accounting_detector", findings=len(results))
        return results

    # ------------------------------------------------------------------

    def _share_inflation_finding(self, pattern: ProtocolPattern) -> Invariant:
        precedents = _rag.query(
            InvariantType.SHARE_ACCOUNTING,
            tags={"erc4626", "share_inflation", "first_deposit"},
        )
        boost = _rag.confidence_boost(precedents)
        evidence_str = _rag.evidence_summary(precedents)

        evidence = [
            "ERC-4626 vault detected WITHOUT dead-shares / virtual-offset protection.",
            "First depositor can mint 1 share, donate assets directly to vault, "
            "then the second depositor receives 0 shares due to rounding (inflation attack).",
        ]
        if evidence_str:
            evidence.append(evidence_str)

        return Invariant(
            type=InvariantType.SHARE_ACCOUNTING,
            severity=InvariantSeverity.HIGH,
            description=(
                "ERC-4626 share inflation attack: vault lacks virtual-offset or dead-shares "
                "protection. First depositor can inflate share price to steal subsequent "
                "depositors' funds. (See Sonne Finance, $20M)."
            ),
            formal_spec=_spec_gen.generate(InvariantType.SHARE_ACCOUNTING, pattern),
            confidence=min(0.75 + boost, 0.95),
            functions_involved=pattern.deposit_functions[:5],
            state_vars_involved=pattern.share_vars[:3],
            historical_precedent=precedents,
            evidence=evidence,
            detector=self.name,
        )

    def _share_round_trip_finding(self, pattern: ProtocolPattern) -> Invariant:
        precedents = _rag.query(
            InvariantType.SHARE_ACCOUNTING,
            tags={"vault", "share_price"},
        )
        boost = _rag.confidence_boost(precedents)
        evidence_str = _rag.evidence_summary(precedents)

        evidence = [
            f"Share-based vault with shares: {pattern.share_vars[:3]}, "
            f"deposits: {pattern.deposit_functions[:3]}.",
            "Round-trip invariant: convertToAssets(convertToShares(x)) <= x.",
        ]
        if evidence_str:
            evidence.append(evidence_str)

        return Invariant(
            type=InvariantType.SHARE_ACCOUNTING,
            severity=InvariantSeverity.MEDIUM,
            description=(
                "Share round-trip invariant: converting assets → shares → assets must not "
                "yield more than the original amount. Share price must be non-decreasing."
            ),
            formal_spec=_spec_gen.generate(InvariantType.SHARE_ACCOUNTING, pattern),
            confidence=min(0.60 + boost, 0.95),
            functions_involved=(pattern.deposit_functions + pattern.withdraw_functions)[:10],
            state_vars_involved=pattern.share_vars[:3],
            historical_precedent=precedents,
            evidence=evidence,
            detector=self.name,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _has_inflation_protection(graph: ProtocolGraph) -> bool:
    """Return True if the vault has virtual-offset or dead-shares protection."""
    all_names = (
        [v.name.lower() for v in graph.state_variables]
        + [f.name.lower() for f in graph.functions]
    )
    return any(
        any(kw in n for kw in _DEAD_SHARE_KW | _VIRTUAL_ASSET_KW)
        for n in all_names
    )
