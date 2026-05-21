"""
Pattern-signature extractor — Phase 10.

Reads the Phase 8 knowledge graph and compiles each interesting node into
a :class:`PatternSignature` that the live :class:`PatternMatcher` can score
incoming mempool transactions against.

Sources walked (in order of precedence):

  1. ``ExploitPattern`` nodes — one signature per attack class. These are
     the broad "this kind of call is suspicious" rules.
  2. ``ValidatedExploit`` nodes — narrower, protocol-specific signatures
     pulled from our own Phase 6 validations.
  3. ``ExternalIncident`` nodes — historical hacks; signatures focus on
     known target functions and victim protocols.

Function selectors for the suspicious calls are computed once from a
curated table of well-known DeFi entrypoints (flash loans, swaps, governance
execution, etc.) and from any function names referenced in the KG node.
"""

from __future__ import annotations

import logging
from typing import Iterable, Optional

from zeropath.knowledge.knowledge import KnowledgeGraphOrchestrator
from zeropath.knowledge.models import KGNode
from zeropath.knowledge.schema import NodeLabel
from zeropath.monitor.models import (
    AlertSeverity,
    MagnitudeBand,
    PatternSignature,
)
from zeropath.sequencer.abi_encoder import function_selector

logger = logging.getLogger(__name__)


# Default suspicious entrypoints per attack class — these are the function
# calls a defender expects to see on the wire when an attack is in flight.
_DEFAULT_SELECTOR_SIGS: dict[str, list[str]] = {
    "flash_loan": [
        "flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)",
        "flashLoanSimple(address,address,uint256,bytes,uint16)",
        "flashLoan(address[],uint256[],bytes)",     # Balancer
        "flash(address,uint256,uint256,bytes)",     # UniV3
    ],
    "oracle_manipulation": [
        "swap(uint256,uint256,address,bytes)",      # UniV2 pair
        "swap(address,bool,int256,uint160,bytes)",  # UniV3 pool
        "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))",
        "exchange(int128,int128,uint256,uint256)",  # Curve
    ],
    "price_manipulation": [
        "swap(uint256,uint256,address,bytes)",
        "exchange(int128,int128,uint256,uint256)",
    ],
    "reentrancy": [
        "withdraw(uint256)",
        "redeem(uint256)",
        "claim()",
    ],
    "access_control": [
        "execute(address,uint256,bytes)",
        "transferOwnership(address)",
        "grantRole(bytes32,address)",
        "upgradeTo(address)",
        "upgradeToAndCall(address,bytes)",
    ],
    "governance": [
        "execute(uint256)",
        "execute(address[],uint256[],bytes[],bytes32)",
        "castVote(uint256,uint8)",
        "queue(uint256)",
    ],
    "composability": [
        "flashLoanSimple(address,address,uint256,bytes,uint16)",
        "swap(uint256,uint256,address,bytes)",
    ],
    "integer_math": [
        "mint(uint256)",
        "redeem(uint256)",
        "deposit(uint256)",
    ],
}


# Per-class severity floor when a signature matches. Tuned to surface
# the most damaging attack classes loudest.
_BASE_SEVERITY: dict[str, AlertSeverity] = {
    "flash_loan": AlertSeverity.HIGH,
    "oracle_manipulation": AlertSeverity.HIGH,
    "price_manipulation": AlertSeverity.HIGH,
    "composability": AlertSeverity.HIGH,
    "reentrancy": AlertSeverity.HIGH,
    "access_control": AlertSeverity.CRITICAL,
    "governance": AlertSeverity.CRITICAL,
    "integer_math": AlertSeverity.MEDIUM,
    "unknown": AlertSeverity.LOW,
}


# Loss thresholds that lift severity by one tier when ``historical_loss_usd``
# crosses them. Calibrated to mainnet incidents.
_LOSS_UPGRADE_HIGH_USD = 10_000_000
_LOSS_UPGRADE_CRITICAL_USD = 100_000_000


def _selectors_for_class(attack_class: str) -> list[str]:
    sigs = _DEFAULT_SELECTOR_SIGS.get(attack_class, [])
    out: list[str] = []
    for sig in sigs:
        try:
            out.append("0x" + function_selector(sig).hex())
        except Exception:
            logger.debug("could not derive selector for %s", sig)
    return out


def _selectors_for_function_names(names: Iterable[str]) -> list[str]:
    """
    Best-effort: derive selectors from bare function names.

    Bare names (no arg list) need a guessed signature. We try a small set
    of common arg shapes; any that produce a valid selector are returned.
    """
    out: list[str] = []
    common_shapes = ["()", "(uint256)", "(address)", "(address,uint256)",
                     "(uint256,uint256)"]
    for name in names:
        if "(" in name:
            try:
                out.append("0x" + function_selector(name).hex())
            except Exception:
                pass
            continue
        for shape in common_shapes:
            try:
                out.append("0x" + function_selector(f"{name}{shape}").hex())
            except Exception:
                pass
    return out


def _severity_for(attack_class: str, loss_usd: int) -> AlertSeverity:
    base = _BASE_SEVERITY.get(attack_class, AlertSeverity.MEDIUM)
    if loss_usd >= _LOSS_UPGRADE_CRITICAL_USD:
        return AlertSeverity.CRITICAL
    if loss_usd >= _LOSS_UPGRADE_HIGH_USD and base.value not in {"critical"}:
        return AlertSeverity.HIGH
    return base


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------


class SignatureExtractor:
    """
    Compile Phase 8 KG nodes into :class:`PatternSignature` rows.

    Parameters
    ----------
    knowledge : KnowledgeGraphOrchestrator | None
        KG source. If None the extractor only produces defaults.
    include_defaults : bool
        Always emit the per-attack-class default signatures (covers the
        case where the KG is empty on first run).
    min_loss_usd_external : int
        External incidents below this loss are skipped — they generate a
        lot of low-signal alerts otherwise.
    """

    def __init__(
        self,
        knowledge: Optional[KnowledgeGraphOrchestrator] = None,
        *,
        include_defaults: bool = True,
        min_loss_usd_external: int = 1_000_000,
    ) -> None:
        self.knowledge = knowledge
        self.include_defaults = include_defaults
        self.min_loss_usd_external = min_loss_usd_external

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self) -> list[PatternSignature]:
        sigs: list[PatternSignature] = []
        if self.include_defaults:
            sigs.extend(self._default_signatures())
        if self.knowledge is not None:
            sigs.extend(self._from_exploit_patterns())
            sigs.extend(self._from_validated_exploits())
            sigs.extend(self._from_external_incidents())
        return self._dedupe(sigs)

    # ------------------------------------------------------------------
    # Sources
    # ------------------------------------------------------------------

    def _default_signatures(self) -> list[PatternSignature]:
        out: list[PatternSignature] = []
        for cls, _sigs in _DEFAULT_SELECTOR_SIGS.items():
            selectors = _selectors_for_class(cls)
            if not selectors:
                continue
            out.append(PatternSignature(
                name=f"default::{cls}",
                attack_class=cls,
                function_selectors=selectors,
                base_severity=_BASE_SEVERITY.get(cls, AlertSeverity.MEDIUM),
                source_kind="default",
                # Selector-only match scores 0.40 (the selector weight);
                # default threshold matches so any tx hitting a dangerous
                # entrypoint fires at least a baseline alert.
                match_threshold=0.40,
            ))
        return out

    def _from_exploit_patterns(self) -> list[PatternSignature]:
        assert self.knowledge is not None
        out: list[PatternSignature] = []
        for node in self.knowledge.store.find_by_label(NodeLabel.EXPLOIT_PATTERN):
            cls = node.properties.get("attack_class", "unknown")
            selectors = _selectors_for_class(cls)
            if not selectors:
                continue
            out.append(PatternSignature(
                name=f"pattern::{cls}",
                attack_class=cls,
                function_selectors=selectors,
                base_severity=_BASE_SEVERITY.get(cls, AlertSeverity.MEDIUM),
                source_kind="exploit_pattern",
                source_node_id=node.id,
                match_threshold=0.50,
            ))
        return out

    def _from_validated_exploits(self) -> list[PatternSignature]:
        assert self.knowledge is not None
        out: list[PatternSignature] = []
        for node in self.knowledge.store.find_by_label(NodeLabel.VALIDATED_EXPLOIT):
            cls = node.properties.get("attack_class", "unknown")
            functions = node.properties.get("functions_involved") or []
            selectors = (
                _selectors_for_class(cls)
                + _selectors_for_function_names(functions)
            )
            if not selectors:
                continue
            loss_usd = int(node.properties.get("profit_usd") or 0)
            out.append(PatternSignature(
                name=f"validated::{node.properties.get('protocol_name', 'unknown')}::{cls}",
                attack_class=cls,
                protocol_name=node.properties.get("protocol_name"),
                function_selectors=list(set(selectors)),
                base_severity=_severity_for(cls, loss_usd),
                source_kind="validated_exploit",
                source_node_id=node.id,
                historical_loss_usd=loss_usd,
                match_threshold=0.55,
            ))
        return out

    def _from_external_incidents(self) -> list[PatternSignature]:
        assert self.knowledge is not None
        out: list[PatternSignature] = []
        for node in self.knowledge.store.find_by_label(NodeLabel.EXTERNAL_INCIDENT):
            loss_usd = int(node.properties.get("loss_usd") or 0)
            if loss_usd < self.min_loss_usd_external:
                continue
            cls = node.properties.get("attack_class", "unknown")
            functions = node.properties.get("affected_functions") or []
            selectors = (
                _selectors_for_class(cls)
                + _selectors_for_function_names(functions)
            )
            if not selectors:
                continue
            target_addresses = [
                a.lower() for a in (node.properties.get("affected_addresses") or [])
                if isinstance(a, str) and a.startswith("0x")
            ]
            out.append(PatternSignature(
                name=f"incident::{node.properties.get('protocol', 'unknown')}::{cls}",
                attack_class=cls,
                protocol_name=node.properties.get("protocol"),
                function_selectors=list(set(selectors)),
                target_addresses=target_addresses,
                base_severity=_severity_for(cls, loss_usd),
                source_kind="external_incident",
                source_node_id=node.id,
                historical_loss_usd=loss_usd,
                match_threshold=0.55,
            ))
        return out

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dedupe(sigs: list[PatternSignature]) -> list[PatternSignature]:
        """Collapse exact-duplicate (name, attack_class) signatures."""
        seen: dict[tuple[str, str], PatternSignature] = {}
        for s in sigs:
            key = (s.name, s.attack_class)
            existing = seen.get(key)
            if existing is None:
                seen[key] = s
                continue
            # Merge selector + address sets
            merged_sels = sorted(set(existing.function_selectors) | set(s.function_selectors))
            merged_addrs = sorted(set(existing.target_addresses) | set(s.target_addresses))
            existing.function_selectors = merged_sels
            existing.target_addresses = merged_addrs
            existing.historical_loss_usd = max(
                existing.historical_loss_usd, s.historical_loss_usd,
            )
        return list(seen.values())
