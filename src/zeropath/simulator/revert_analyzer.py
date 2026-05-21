"""
Revert analyzer — Phase 5.

Spec (phases.md, PHASE 5, "Revert analysis"):
    "When a sequence fails (reverts), capture the full revert reason, the
     call stack at revert, and the state delta up to the revert point.
     Feed this back to Phase 4 as mutation guidance: 'failed at step 3
     because allowance was insufficient — try approve() before
     transferFrom()'."

Two responsibilities:

1. **Decode** raw return data into a human-readable revert string.
2. **Suggest** a concrete mutation operator the Phase 4 mutation engine could
   apply, based on the decoded reason and the surrounding call sequence.

We avoid an external dependency on the Foundry trace decoder by recognising
the two standard Solidity revert wrappers (``Error(string)`` and
``Panic(uint256)``) and the most common 4-byte error selectors we expect to
see in DeFi flows.
"""

from __future__ import annotations

import logging
from typing import Optional

from zeropath.sequencer.abi_encoder import function_selector
from zeropath.simulator.models import RevertInfo

logger = logging.getLogger(__name__)


# 0x08c379a0 — Error(string)
_ERROR_STRING_SELECTOR = "0x08c379a0"
# 0x4e487b71 — Panic(uint256)
_PANIC_SELECTOR = "0x4e487b71"

# Solidity Panic codes per the spec
_PANIC_CODES: dict[int, str] = {
    0x01: "assertion failed",
    0x11: "arithmetic over/underflow",
    0x12: "division or modulo by zero",
    0x21: "invalid enum value",
    0x22: "incorrectly encoded storage byte array",
    0x31: ".pop() on an empty array",
    0x32: "array index out of bounds",
    0x41: "allocation too large or out of memory",
    0x51: "invalid internal function call",
}


# Well-known custom error selectors. Computed lazily on first use.
def _make_custom_error_table() -> dict[str, str]:
    table: dict[str, str] = {}
    for sig, label in [
        # ERC-20-ish
        ("InsufficientAllowance(address,uint256)", "ERC20 insufficient allowance"),
        ("InsufficientBalance(uint256,uint256)", "ERC20 insufficient balance"),
        ("ERC20InsufficientBalance(address,uint256,uint256)", "ERC20 insufficient balance (OZ v5)"),
        ("ERC20InsufficientAllowance(address,uint256,uint256)", "ERC20 insufficient allowance (OZ v5)"),
        # Access control
        ("Unauthorized()", "unauthorized caller"),
        ("OwnableUnauthorizedAccount(address)", "Ownable: caller is not the owner"),
        ("AccessControlUnauthorizedAccount(address,bytes32)", "missing role"),
        # Reentrancy
        ("ReentrancyGuardReentrantCall()", "reentrancy guard triggered"),
        # Pausable
        ("EnforcedPause()", "contract is paused"),
        # Slippage / DEX
        ("SlippageExceeded()", "slippage tolerance exceeded"),
        # Flash-loan
        ("FlashLoanNotRepaid()", "flash loan not repaid in callback"),
    ]:
        sel = "0x" + function_selector(sig).hex()
        table[sel] = label
    return table


_CUSTOM_ERROR_TABLE: Optional[dict[str, str]] = None


def _custom_error_table() -> dict[str, str]:
    global _CUSTOM_ERROR_TABLE
    if _CUSTOM_ERROR_TABLE is None:
        _CUSTOM_ERROR_TABLE = _make_custom_error_table()
    return _CUSTOM_ERROR_TABLE


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------


def decode_revert(return_data_hex: Optional[str]) -> str:
    """Best-effort decode of raw revert return data into a human string."""
    if not return_data_hex or return_data_hex == "0x":
        return "execution reverted (no reason)"
    raw = return_data_hex.lower()
    if not raw.startswith("0x"):
        raw = "0x" + raw

    # Error(string)
    if raw.startswith(_ERROR_STRING_SELECTOR):
        try:
            payload = bytes.fromhex(raw[2 + 8:])  # strip 0x + selector
            # offset (32) + length (32) + data
            length = int.from_bytes(payload[32:64], "big")
            msg = payload[64:64 + length].decode("utf-8", errors="replace")
            return msg
        except Exception:
            return "Error(string) — undecodable payload"

    # Panic(uint256)
    if raw.startswith(_PANIC_SELECTOR):
        try:
            code = int(raw[2 + 8:], 16)
            return f"Panic({hex(code)}): {_PANIC_CODES.get(code, 'unknown panic')}"
        except Exception:
            return "Panic(uint256) — undecodable payload"

    # Custom errors
    sel = raw[:10]
    label = _custom_error_table().get(sel)
    if label:
        return f"{label} (selector {sel})"

    # Unknown selector — pass through
    return f"custom revert (selector {sel})"


# ---------------------------------------------------------------------------
# Mutation suggester
# ---------------------------------------------------------------------------


_SUGGESTION_RULES: list[tuple[str, str]] = [
    # (substring match → suggested mutation hint).
    # Substrings are matched against the lower-cased decoded reason, so both
    # spaced ("insufficient allowance") and PascalCase-derived ("reentrancy")
    # variants need to be covered.
    ("insufficient allowance", "Insert approve() with type(uint256).max before this step."),
    ("insufficient balance", "Increase flash-loan amount or add deal() in Foundry test setup."),
    ("slippage", "Loosen minAmountOut / increase amountIn — try mutation 'scale_amount_10x'."),
    ("reentrancy", "Reorder or split: try mutation 'reorder_inner_steps'."),
    ("paused", "Hypothesis is infeasible — skip until protocol is unpaused."),
    ("ownable", "Access-control gated — escalate via 'AccessControlAgent' or impersonate owner."),
    ("missing role", "Try anvil_impersonateAccount on a holder of the required role."),
    ("overflow", "Reduce scale: try mutation 'scale_amount_0.1x' (custom)."),
    ("division", "Avoid zero-divisor — vary the amount param away from boundary."),
    ("flash loan not repaid", "Re-order so the repay transfer precedes the callback return."),
    ("array index out of bounds", "Inspect indices — bounds may depend on prior pool state."),
]


def suggest_mutation(decoded_reason: str) -> Optional[str]:
    """Map a decoded revert string to a concrete mutation hint."""
    if not decoded_reason:
        return None
    needle = decoded_reason.lower()
    for kw, hint in _SUGGESTION_RULES:
        if kw in needle:
            return hint
    return None


# ---------------------------------------------------------------------------
# Public analyzer
# ---------------------------------------------------------------------------


class RevertAnalyzer:
    """Convert raw revert telemetry into a structured ``RevertInfo``."""

    def analyse(
        self,
        *,
        step: int,
        return_data_hex: Optional[str],
        call_stack: Optional[list[str]] = None,
    ) -> RevertInfo:
        reason = decode_revert(return_data_hex)
        suggestion = suggest_mutation(reason)
        return RevertInfo(
            step=step,
            reason=reason,
            call_stack=call_stack or [],
            raw_return_data=return_data_hex,
            suggested_mutation=suggestion,
        )
