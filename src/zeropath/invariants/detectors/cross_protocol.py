"""
Cross-protocol composability invariant detector.

The most dangerous DeFi attacks are multi-protocol: one protocol's oracle,
another's flash loan, a third's AMM — composed in a single transaction.

Detection strategy:
  1. Count external dependencies — more = larger composability attack surface.
  2. Check if any external dep is itself a DeFi primitive (AMM, lending, oracle).
  3. Cross-reference: does the protocol use external flash loans (Aave, dYdX)?
  4. Detect bridge contracts (highest cross-protocol risk class).
  5. Detect aggregators with unverified calldata pass-through.
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

# External dep name/interface patterns signalling cross-protocol risk
_FLASH_SOURCE_KW = {"aave", "dydx", "uniswap", "balancer", "makerdao", "euler"}
_BRIDGE_KW = {"bridge", "crosschain", "relay", "portal", "wormhole", "hop"}
_AGGREGATOR_KW = {"aggregator", "router", "swap", "oneinch", "paraswap", "0x"}
_LENDING_DEP_KW = {"compound", "aave", "maker", "euler", "benqi"}


class CrossProtocolDetector(BaseDetector):
    """Detect cross-protocol composability invariants."""

    name = "cross_protocol"

    def detect(
        self,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[Invariant]:
        results: list[Invariant] = []

        if not graph.external_dependencies:
            return results

        dep_names_lower = [d.name.lower() for d in graph.external_dependencies]

        flash_sources = [n for n in dep_names_lower if any(kw in n for kw in _FLASH_SOURCE_KW)]
        bridge_deps = [n for n in dep_names_lower if any(kw in n for kw in _BRIDGE_KW)]
        aggregator_deps = [n for n in dep_names_lower if any(kw in n for kw in _AGGREGATOR_KW)]

        # Bridge contracts — highest risk
        if bridge_deps or _is_bridge_contract(graph):
            results.append(self._bridge_finding(pattern, bridge_deps))

        # Aggregator with potential calldata injection
        if aggregator_deps:
            results.append(self._aggregator_finding(pattern, aggregator_deps))

        # Flash loan source available externally
        if flash_sources and (pattern.has_oracle or pattern.borrow_functions):
            results.append(self._flash_composability_finding(
                pattern, flash_sources,
            ))

        # General cross-protocol finding for high external dependency count
        n_deps = len(graph.external_dependencies)
        if n_deps >= 3:
            results.append(self._high_dep_count_finding(pattern, n_deps))

        logger.debug("cross_protocol_detector", findings=len(results))
        return results

    # ------------------------------------------------------------------

    def _bridge_finding(
        self, pattern: ProtocolPattern, bridge_deps: list[str]
    ) -> Invariant:
        precedents = _rag.query(
            InvariantType.CROSS_PROTOCOL,
            tags={"bridge", "cross_protocol"},
        )
        boost = _rag.confidence_boost(precedents)
        evidence_str = _rag.evidence_summary(precedents)

        evidence = [
            f"Bridge/cross-chain dependencies detected: {bridge_deps[:3]}.",
            "Cross-chain message validation must verify guardian/validator set and "
            "reject replayed or spoofed messages.",
        ]
        if evidence_str:
            evidence.append(evidence_str)

        return Invariant(
            type=InvariantType.CROSS_PROTOCOL,
            severity=InvariantSeverity.CRITICAL,
            description=(
                "Bridge cross-protocol invariant: all cross-chain messages must be "
                "validated against the current authorised guardian/validator set. "
                "Spoofed or replayed messages must be rejected. "
                "(See Ronin $625M, Wormhole $320M, Nomad $190M)."
            ),
            formal_spec=_spec_gen.generate(InvariantType.CROSS_PROTOCOL, pattern),
            confidence=min(0.75 + boost, 0.95),
            historical_precedent=precedents,
            evidence=evidence,
            detector=self.name,
        )

    def _aggregator_finding(
        self, pattern: ProtocolPattern, agg_deps: list[str]
    ) -> Invariant:
        precedents = _rag.query(
            InvariantType.CROSS_PROTOCOL,
            tags={"calldata_injection", "allowance"},
        )
        boost = _rag.confidence_boost(precedents)
        evidence_str = _rag.evidence_summary(precedents)

        evidence = [
            f"Swap aggregator dependencies: {agg_deps[:3]}.",
            "Aggregators that pass calldata directly to external contracts risk "
            "calldata injection — arbitrary external calls from protocol context.",
        ]
        if evidence_str:
            evidence.append(evidence_str)

        return Invariant(
            type=InvariantType.CROSS_PROTOCOL,
            severity=InvariantSeverity.HIGH,
            description=(
                "Aggregator calldata safety: swap aggregator integrations must validate "
                "that passed calldata cannot be weaponised to call arbitrary targets with "
                "protocol context. (See Transit Swap $21M)."
            ),
            formal_spec=_spec_gen.generate(InvariantType.CROSS_PROTOCOL, pattern),
            confidence=min(0.60 + boost, 0.95),
            historical_precedent=precedents,
            evidence=evidence,
            detector=self.name,
        )

    def _flash_composability_finding(
        self, pattern: ProtocolPattern, flash_sources: list[str]
    ) -> Invariant:
        precedents = _rag.query(
            InvariantType.CROSS_PROTOCOL,
            tags={"flash_loan", "oracle", "composability"},
        )
        boost = _rag.confidence_boost(precedents)
        evidence_str = _rag.evidence_summary(precedents)

        evidence = [
            f"Flash loan sources in scope: {flash_sources[:3]}.",
            "Protocol has oracle dependency + lending/deposit functions.",
            "Attacker can compose: flash loan → oracle manipulation → exploit → repay.",
        ]
        if evidence_str:
            evidence.append(evidence_str)

        return Invariant(
            type=InvariantType.CROSS_PROTOCOL,
            severity=InvariantSeverity.CRITICAL,
            description=(
                "Flash loan composability: external flash loan sources are in scope and "
                "this protocol reads an oracle in state-mutating functions. "
                "Multi-protocol attack: borrow flash loan → manipulate oracle → exploit → repay. "
                "(See bZx $350K, Cream Finance $130M)."
            ),
            formal_spec=_spec_gen.generate(InvariantType.CROSS_PROTOCOL, pattern),
            confidence=min(0.80 + boost, 0.95),
            cross_protocol_scope=flash_sources[:5],
            historical_precedent=precedents,
            evidence=evidence,
            detector=self.name,
        )

    def _high_dep_count_finding(
        self, pattern: ProtocolPattern, n_deps: int
    ) -> Invariant:
        precedents = _rag.query(InvariantType.CROSS_PROTOCOL)
        boost = _rag.confidence_boost(precedents)

        evidence = [
            f"Protocol has {n_deps} external dependencies — large composability surface.",
            "Each external dependency is a trust assumption that must hold simultaneously.",
        ]

        return Invariant(
            type=InvariantType.CROSS_PROTOCOL,
            severity=InvariantSeverity.MEDIUM,
            description=(
                f"Cross-protocol composability: {n_deps} external protocol dependencies "
                f"create a large attack surface. All trust assumptions must hold simultaneously."
            ),
            formal_spec=_spec_gen.generate(InvariantType.CROSS_PROTOCOL, pattern),
            confidence=min(0.45 + boost, 0.95),
            historical_precedent=precedents,
            evidence=evidence,
            detector=self.name,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_bridge_contract(graph: ProtocolGraph) -> bool:
    """Detect bridge contracts from function/variable naming."""
    all_names = (
        [f.name.lower() for f in graph.functions]
        + [v.name.lower() for v in graph.state_variables]
    )
    return any(any(kw in n for kw in _BRIDGE_KW) for n in all_names)
