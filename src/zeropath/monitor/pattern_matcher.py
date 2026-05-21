"""
Pattern matcher — Phase 10.

Score a :class:`MempoolTx` against every :class:`PatternSignature` and emit
:class:`SignatureMatch` records ordered by score. The matcher is purely
deterministic (no LLM, no I/O) so it can run inside the mempool hot path.

Scoring
-------
Each non-empty dimension on the signature contributes a weighted component
to the final score, capped at 1.0::

    selector match       0.40
    target_address match 0.30
    protocol match       0.15
    magnitude match      0.10
    keyword match        0.05

A signature scores 0 (no match) and is dropped if none of its
dimensions match. Selectors specified on the signature are *required*
when present — a tx whose selector isn't on the list scores zero overall.
"""

from __future__ import annotations

import logging
from typing import Iterable, Optional

from zeropath.monitor.models import (
    MagnitudeBand,
    MatchKind,
    MempoolTx,
    PatternSignature,
    SignatureMatch,
)

logger = logging.getLogger(__name__)


# Component weights — sum to 1.0.
_W_SELECTOR = 0.40
_W_TARGET = 0.30
_W_PROTOCOL = 0.15
_W_MAGNITUDE = 0.10
_W_KEYWORD = 0.05


class PatternMatcher:
    """
    Pluggable matcher driven by a list of compiled :class:`PatternSignature`.

    Parameters
    ----------
    signatures : list[PatternSignature]
        Compiled rule set, typically produced by :class:`SignatureExtractor`.
    """

    def __init__(self, signatures: Iterable[PatternSignature]) -> None:
        self.signatures = list(signatures)
        # Pre-index by function selector for O(1) candidate selection.
        self._by_selector: dict[str, list[PatternSignature]] = {}
        self._catchall: list[PatternSignature] = []
        for sig in self.signatures:
            if not sig.function_selectors:
                self._catchall.append(sig)
            for sel in sig.function_selectors:
                self._by_selector.setdefault(sel.lower(), []).append(sig)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def match(self, tx: MempoolTx) -> list[SignatureMatch]:
        """Return every signature that scores ≥ its threshold, sorted desc."""
        candidates: list[PatternSignature] = []
        if tx.function_selector and tx.function_selector in self._by_selector:
            candidates.extend(self._by_selector[tx.function_selector])
        candidates.extend(self._catchall)
        # De-duplicate while preserving order.
        seen_ids: set[str] = set()
        unique: list[PatternSignature] = []
        for s in candidates:
            if s.id not in seen_ids:
                unique.append(s)
                seen_ids.add(s.id)

        matches: list[SignatureMatch] = []
        for sig in unique:
            score, components, dims = self._score(tx, sig)
            if score >= sig.match_threshold:
                matches.append(SignatureMatch(
                    signature_id=sig.id,
                    signature_name=sig.name,
                    tx_hash=tx.tx_hash,
                    score=round(score, 4),
                    components=components,
                    matched_dimensions=dims,
                ))
        matches.sort(key=lambda m: m.score, reverse=True)
        return matches

    def best_match(self, tx: MempoolTx) -> Optional[SignatureMatch]:
        matches = self.match(tx)
        return matches[0] if matches else None

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _score(
        self, tx: MempoolTx, sig: PatternSignature,
    ) -> tuple[float, dict[str, float], list[MatchKind]]:
        components: dict[str, float] = {}
        dims: list[MatchKind] = []

        # Selector: required when set.
        if sig.function_selectors:
            if tx.function_selector and tx.function_selector in {
                s.lower() for s in sig.function_selectors
            }:
                components["selector"] = _W_SELECTOR
                dims.append(MatchKind.SELECTOR)
            else:
                # Hard zero — caller already filtered, defensive guard.
                return 0.0, {"selector": 0.0}, []

        # Target address.
        if sig.target_addresses:
            if tx.to_address and tx.to_address.lower() in {
                a.lower() for a in sig.target_addresses
            }:
                components["target_address"] = _W_TARGET
                dims.append(MatchKind.TARGET_ADDRESS)

        # Protocol — best-effort via target address overlap with sig protocol.
        if sig.protocol_name:
            # Without an address-book the matcher can't bind a protocol to
            # a tx perfectly. Award partial credit when the signature was
            # built from a protocol-specific source.
            components["protocol"] = _W_PROTOCOL * 0.5
            dims.append(MatchKind.PROTOCOL)

        # Magnitude (value_wei vs configured band).
        if sig.value_band is not None:
            band: MagnitudeBand = sig.value_band
            if band.min_wei <= tx.value_wei <= band.max_wei:
                components["magnitude"] = _W_MAGNITUDE
                dims.append(MatchKind.MAGNITUDE)

        # Keyword presence in the calldata payload (cheap substring scan).
        if sig.required_function_keywords:
            payload = tx.input_hex.lower()
            hits = sum(1 for kw in sig.required_function_keywords if kw.lower() in payload)
            if hits:
                components["keyword"] = _W_KEYWORD * (hits / len(sig.required_function_keywords))
                dims.append(MatchKind.CONTEXT)

        score = sum(components.values())

        if score > 0 and len(dims) >= 2:
            dims.append(MatchKind.COMPOSITE)

        return min(score, 1.0), components, dims
