"""Heuristic detection of ERC4626 share-inflation mitigations (anti-conditions).

The donation/first-deposit share inflation attack only works when a vault is
*unprotected*. Real vaults frequently ship one of a handful of well-known
mitigations that defeat it:

* virtual shares / a decimals offset (OpenZeppelin ERC4626)
* dead shares / a minimum-liquidity mint on the first deposit
* internal asset accounting whose ``totalAssets`` ignores direct donations
* a first-deposit guard that forbids a tiny opening share supply
* a deposit cap or access restriction that makes the victim path unrealistic

This module scans Solidity source text for those patterns so the judge can
block or downgrade a candidate whose target vault looks protected. Detection is
deliberately **heuristic** (regex over source, not full semantic analysis); every
hit is labelled ``confidence="heuristic"`` and callers must surface that.

Scope: this supports the ERC4626 inflation benchmark fixture and simple
vault-like contracts. It is not a general ERC4626 analyzer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

INFLATION_BUG_CLASSES = {"erc4626_share_inflation"}


@dataclass(frozen=True)
class GuardHit:
    """One detected anti-condition (inflation mitigation)."""

    name: str
    detail: str
    confidence: str = "heuristic"


# A `totalAssets` function body. Vault bodies are simple (no nested braces), so a
# non-greedy match to the first closing brace is sufficient for the heuristic.
_TOTAL_ASSETS_RE = re.compile(
    r"function\s+totalassets\s*\([^)]*\)[^{]*\{(?P<body>[^}]*)\}", re.DOTALL
)

_VIRTUAL_SHARES_RE = re.compile(
    r"decimalsoffset|_decimals_offset|virtual\s*shares|virtual\s*assets|virtual_(?:shares|assets)"
)
_DEAD_SHARES_RE = re.compile(
    r"minimum_?liquidity|dead_?shares|mint\(\s*address\(0|address\(0xdead\)"
)
_FIRST_DEPOSIT_RE = re.compile(
    r"require\(\s*shares\s*[>!]=?\s*0|min_?(?:initial|first)_?deposit|first_?deposit_?guard|initialdeposit"
)
_DEPOSIT_CAP_RE = re.compile(
    r"deposit_?cap|tvl_?cap|max_?total_?(?:assets|deposit)|whitelist|whennotpaused|onlywhitelisted|require\([^;]*paused"
)


def detect_share_inflation_guards(source: str) -> list[GuardHit]:
    """Return anti-conditions detected in ``source`` (Solidity), if any.

    An empty list means no mitigation was recognised, i.e. the vault looks
    donation/first-deposit sensitive. This does not prove the vault is exploitable
    -- only that none of the known protections were found.
    """

    if not source:
        return []
    text = source.lower()
    hits: list[GuardHit] = []

    if _VIRTUAL_SHARES_RE.search(text):
        hits.append(
            GuardHit(
                "virtual_shares",
                "Vault appears to use virtual shares / a decimals offset, which "
                "blunts donation-based share-price manipulation.",
            )
        )
    if _DEAD_SHARES_RE.search(text):
        hits.append(
            GuardHit(
                "dead_shares",
                "Vault appears to mint dead shares / a minimum liquidity floor, "
                "which prevents a near-empty share supply on the first deposit.",
            )
        )
    if _internal_accounting(text):
        hits.append(
            GuardHit(
                "internal_accounting",
                "totalAssets() does not read the raw token balance, so direct "
                "donations to the vault do not move the share price.",
            )
        )
    if _FIRST_DEPOSIT_RE.search(text):
        hits.append(
            GuardHit(
                "first_deposit_guard",
                "Deposit path appears to guard the first/opening deposit (e.g. a "
                "minimum initial deposit or non-zero-shares check).",
            )
        )
    if _DEPOSIT_CAP_RE.search(text):
        hits.append(
            GuardHit(
                "deposit_cap",
                "Vault appears to enforce a deposit cap, pause, or allowlist, which "
                "can make the victim deposit path unrealistic.",
            )
        )
    return hits


def _internal_accounting(text_lc: str) -> bool:
    """True when totalAssets() exists but does not read the raw token balance."""

    match = _TOTAL_ASSETS_RE.search(text_lc)
    if not match:
        return False
    return "balanceof" not in match.group("body")


def summarize_guards(hits: list[GuardHit]) -> str:
    """One-line, human-readable summary of detected guards."""

    if not hits:
        return "none detected"
    return ", ".join(f"{hit.name} ({hit.confidence})" for hit in hits)


__all__ = [
    "GuardHit",
    "INFLATION_BUG_CLASSES",
    "detect_share_inflation_guards",
    "summarize_guards",
]
