"""
Remediation suggestion engine — Phase 9.

Generates per-attack-class fix recommendations grounded in well-known DeFi
defensive patterns. The output is plain Markdown so it can be embedded
directly in the finding's "Recommended Fix" section.

The recommendations are intentionally concrete (named libraries, exact
modifier patterns, specific timeouts) rather than generic security advice —
auditors and protocol teams need actionable steps, not platitudes.
"""

from __future__ import annotations

from typing import Optional

from zeropath.adversarial.models import AttackClass


# Per-class default remediation. Keyed by AttackClass.value (string) so the
# table is portable across runs where the enum hasn't been imported.
_REMEDIATION_TABLE: dict[str, dict[str, str]] = {
    AttackClass.ORACLE_MANIPULATION.value: {
        "headline": "Replace spot prices with a TWAP oracle (≥30 min window).",
        "details": (
            "1. Never read `getReserves()` or `slot0()` directly for lending or "
            "liquidation logic — these are single-block manipulable.\n"
            "2. Use Chainlink's `AggregatorV3Interface` for blue-chip pairs; "
            "validate `updatedAt` is within `heartbeat + 1 hour`.\n"
            "3. For long-tail assets, wrap Uniswap V3 with an EMA-based TWAP "
            "(Uniswap V3 `OracleLibrary.consult()` with `secondsAgo ≥ 1800`).\n"
            "4. Cap movement: revert if the oracle price changed by more than X% "
            "vs. the prior block."
        ),
        "references": [
            "https://docs.chain.link/data-feeds/price-feeds#monitoring-data-feeds",
            "https://docs.uniswap.org/concepts/protocol/oracle",
        ],
    },
    AttackClass.PRICE_MANIPULATION.value: {
        "headline": "Treat any AMM-derived price as adversarial without a TWAP.",
        "details": (
            "Apply the same controls as Oracle Manipulation. Additionally:\n"
            "- Bound trade size to ≤1% of pool TVL when using on-chain swaps for "
            "pricing.\n"
            "- Sample at least two independent venues and reject if disagreement "
            "exceeds 50 bps."
        ),
        "references": [
            "https://chain.link/education-hub/flash-loans",
        ],
    },
    AttackClass.REENTRANCY.value: {
        "headline": "Apply Checks-Effects-Interactions and add a ReentrancyGuard.",
        "details": (
            "1. Update state variables BEFORE any external call.\n"
            "2. Inherit from OpenZeppelin's `ReentrancyGuard` and tag every "
            "function that touches mutable balances with `nonReentrant`.\n"
            "3. For cross-function reentrancy (ERC-721 callbacks, ERC-777 "
            "hooks), add per-token reentrancy locks.\n"
            "4. Audit `delegatecall`s separately — guards on the wrapping "
            "contract do not protect against state corruption via delegate."
        ),
        "references": [
            "https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard",
            "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
        ],
    },
    AttackClass.ACCESS_CONTROL.value: {
        "headline": "Centralise role checks via OpenZeppelin AccessControl.",
        "details": (
            "1. Replace ad-hoc `require(msg.sender == owner)` checks with the "
            "OpenZeppelin `AccessControl` role registry.\n"
            "2. Make all admin role transfers go through a 2-step "
            "`pendingOwner` flow (use `Ownable2Step`).\n"
            "3. Put privileged functions behind a multisig (Safe) + 48-hour "
            "timelock.\n"
            "4. Emit `RoleGranted`/`RoleRevoked` events on every grant so "
            "monitoring can alert on unexpected privileged calls."
        ),
        "references": [
            "https://docs.openzeppelin.com/contracts/4.x/access-control",
        ],
    },
    AttackClass.FLASH_LOAN.value: {
        "headline": "Bound per-block state changes to defeat atomic capital.",
        "details": (
            "1. Add a per-block volume cap on functions that mint shares or "
            "issue debt (e.g. ≤2% of TVL per block).\n"
            "2. Settle prices from an oracle, NOT from the spot AMM that the "
            "attacker can move within the loan.\n"
            "3. For lending positions, enforce a minimum hold time before "
            "withdraw / borrow against newly-deposited collateral.\n"
            "4. Where atomicity is required by design, validate post-state "
            "invariants (`totalAssets / totalShares` ratio within band)."
        ),
        "references": [
            "https://chain.link/education-hub/flash-loans",
        ],
    },
    AttackClass.COMPOSABILITY.value: {
        "headline": "Treat every external protocol call as adversarial input.",
        "details": (
            "1. Pin integrations to specific protocol versions; assert the "
            "external contract code-hash on initialise.\n"
            "2. Use circuit breakers that revert when an external read deviates "
            "from a moving average.\n"
            "3. Don't accept arbitrary tokens as collateral — maintain an "
            "allowlist with per-token risk parameters."
        ),
        "references": [
            "https://blog.openzeppelin.com/cross-protocol-composability-risks/",
        ],
    },
    AttackClass.GOVERNANCE.value: {
        "headline": "Add a 48-hour timelock and quorum gating.",
        "details": (
            "1. Route every privileged proposal through OpenZeppelin "
            "`TimelockController` with a delay ≥ 48 hours.\n"
            "2. Require quorum ≥ 4% of token supply AND ≥10 unique voters.\n"
            "3. Lock voting power snapshots to the proposal block (use "
            "`ERC20Votes` checkpoints) to neutralise flash-loaned vote attacks.\n"
            "4. Emit `ProposalQueued` events to support off-chain monitoring."
        ),
        "references": [
            "https://docs.openzeppelin.com/contracts/4.x/governance",
        ],
    },
    AttackClass.INTEGER_MATH.value: {
        "headline": "Use Solidity ≥0.8 + explicit fixed-point math.",
        "details": (
            "1. Compile with Solidity ≥0.8 so over/underflow reverts by default.\n"
            "2. For division, always check `denominator > 0` before dividing.\n"
            "3. Use `PRBMath` / `FixedPointMathLib` for token-amount × ratio "
            "operations — never roll your own.\n"
            "4. Round in favour of the protocol on share/asset conversions to "
            "block one-wei donation attacks."
        ),
        "references": [
            "https://github.com/transmissions11/solmate",
            "https://github.com/PaulRBerg/prb-math",
        ],
    },
}


_FALLBACK = {
    "headline": "Address the specific weakness identified in the proof of concept.",
    "details": (
        "No class-specific template was matched for this attack class. The "
        "auditor should map the proof-of-concept transactions to the affected "
        "function and design a targeted fix (state ordering change, input "
        "validation, or invariant enforcement)."
    ),
    "references": [
        "https://consensys.github.io/smart-contract-best-practices/",
    ],
}


class RemediationEngine:
    """Produce per-finding remediation markdown blocks."""

    def __init__(self, table: Optional[dict[str, dict[str, str]]] = None) -> None:
        self.table = dict(table or _REMEDIATION_TABLE)

    def suggest_markdown(self, attack_class: str) -> str:
        rec = self.table.get(attack_class, _FALLBACK)
        out: list[str] = [f"**{rec['headline']}**", "", rec["details"]]
        refs = rec.get("references") or []
        if refs:
            out += ["", "_References:_"]
            out += [f"- {r}" for r in refs]
        return "\n".join(out)

    def suggest_headline(self, attack_class: str) -> str:
        rec = self.table.get(attack_class, _FALLBACK)
        return rec["headline"]

    def known_classes(self) -> list[str]:
        return list(self.table.keys())
