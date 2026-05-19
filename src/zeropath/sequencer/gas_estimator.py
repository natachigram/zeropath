"""
Gas estimator + profit pruner — Phase 4.

Spec (phases.md, PHASE 4 critical additions, "Gas optimization"):
    "Include a gas estimator. Sequences that cost more gas than the potential
     profit are invalid and should be pruned early, not after simulation."

Two layers:

* :class:`GasEstimator` populates ``TxCall.estimated_gas`` and
  ``TransactionSequence.total_gas_estimate`` using a heuristic table keyed
  on call type, encoding, and rough function name. Cheaper than running
  ``eth_estimateGas`` against an RPC, and good enough to weed out clearly
  unprofitable sequences before Phase 5 simulation.

* :func:`prune_unprofitable` drops sequences whose gas cost at the supplied
  gas price exceeds their estimated profit.

The estimator is deliberately conservative — it would rather over-estimate
gas (causing a borderline-profitable sequence to be pruned) than send the
simulator down a known dead-end.
"""

from __future__ import annotations

import logging
import re
from typing import Iterable

from zeropath.sequencer.models import (
    CallEncoding,
    CallerType,
    SequenceStatus,
    TransactionSequence,
    TxCall,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-call heuristic table
# ---------------------------------------------------------------------------
#
# Numbers are mainnet medians from public flashbots/etherscan data. They are
# intentionally rounded up so a sequence flagged as profitable here remains
# profitable under realistic post-execution gas.

_BASE_TX_GAS = 21_000

_FUNCTION_GAS_HINTS: dict[str, int] = {
    # ERC-20
    "approve":            55_000,
    "transfer":           65_000,
    "transferFrom":       80_000,
    "balanceOf":          5_000,
    # Aave V3
    "flashLoan":          600_000,
    "executeOperation":   400_000,  # callback body — depends on payload
    "supply":             280_000,
    "borrow":             400_000,
    "repay":              250_000,
    "withdraw":           280_000,
    "liquidationCall":    500_000,
    # Compound / cToken
    "mint":               220_000,
    "redeem":             220_000,
    "liquidateBorrow":    500_000,
    # Uniswap
    "swap":               150_000,
    "exactInputSingle":   180_000,
    "exactInput":         220_000,
    "swapExactTokensForTokens": 200_000,
    "getReserves":        5_000,
    "slot0":              5_000,
    # Chainlink
    "latestRoundData":    8_000,
    "latestAnswer":       6_000,
    # Governance
    "propose":            300_000,
    "castVote":           100_000,
    "queue":              150_000,
    "execute":            500_000,
    # Curve
    "exchange":           220_000,
    "exchange_underlying":280_000,
    "add_liquidity":      300_000,
    "remove_liquidity":   250_000,
}

_ENCODING_OVERHEAD = {
    CallEncoding.SOLIDITY_CALL: 0,
    CallEncoding.LOW_LEVEL_CALL: 1_500,   # extra abi.encode + call wrapper
    CallEncoding.DELEGATECALL: 3_000,     # delegatecall + storage handoff
    CallEncoding.ETH_TRANSFER: 9_000,     # 2300 stipend + ~6700 SLOAD/STORE
    CallEncoding.STATIC_CALL: 0,
}


def _function_name(signature: str | None) -> str | None:
    if not signature:
        return None
    m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)", signature)
    return m.group(1) if m else None


def _calldata_byte_cost(call: TxCall) -> int:
    """
    EIP-2028 calldata cost: 4 gas per zero byte, 16 per non-zero byte.

    Falls back to a size estimate from ``calldata_expr`` length when no
    concrete ``calldata_hex`` has been encoded yet.
    """
    if call.calldata_hex:
        raw = call.calldata_hex[2:] if call.calldata_hex.startswith("0x") else call.calldata_hex
        try:
            bytestr = bytes.fromhex(raw)
        except ValueError:
            return 16 * (len(raw) // 2)
        zeros = bytestr.count(0)
        nonzeros = len(bytestr) - zeros
        return 4 * zeros + 16 * nonzeros
    # Rough fallback: 4 bytes selector + ~32 bytes per visible argument
    arg_count = call.calldata_expr.count(",") + (1 if call.calldata_expr.strip() else 0)
    return 16 * (4 + 32 * max(arg_count, 0))


class GasEstimator:
    """
    Heuristic per-call + total gas estimator.

    Parameters
    ----------
    default_per_call : int
        Baseline gas when no heuristic matches. 100_000 covers most simple
        function calls without inflating an oracle read.
    """

    def __init__(self, default_per_call: int = 100_000) -> None:
        self.default_per_call = default_per_call

    def estimate_call(self, call: TxCall) -> int:
        # Honour an explicit estimate from the builder.
        if call.estimated_gas:
            return call.estimated_gas

        fn = _function_name(call.function_signature)
        base = _FUNCTION_GAS_HINTS.get(fn, self.default_per_call) if fn else self.default_per_call
        overhead = _ENCODING_OVERHEAD.get(call.encoding, 0)
        cdata = _calldata_byte_cost(call)
        # Caller cost: tx-from-EOA pays 21k base; calls from a contract don't.
        tx_base = _BASE_TX_GAS if call.caller_type == CallerType.ATTACKER_EOA else 0
        # Pre/post Solidity assertions add SLOAD + comparison gas.
        assertion_cost = 2_500 * (len(call.pre_assertions) + len(call.post_assertions))

        total = base + overhead + cdata + tx_base + assertion_cost
        return total

    def estimate_sequence(self, sequence: TransactionSequence) -> int:
        """Estimate gas for every call and the sequence total."""
        total = 0
        for call in sequence.calls:
            est = self.estimate_call(call)
            call.estimated_gas = est
            total += est
        sequence.total_gas_estimate = total
        return total


# ---------------------------------------------------------------------------
# Profit-vs-gas pruner
# ---------------------------------------------------------------------------


def _profit_wei_from_estimate(seq: TransactionSequence) -> int | None:
    """
    Best-effort numeric profit from ``profit_estimate.min_profit_expression``.

    Returns None when the expression is opaque (e.g. a Solidity expression).
    Pruner then errs on the side of keeping the sequence.
    """
    if seq.estimated_profit_wei:
        return seq.estimated_profit_wei
    if not seq.profit_estimate:
        return None
    expr = seq.profit_estimate.min_profit_expression.strip()
    # Direct integer
    if re.fullmatch(r"-?\d+", expr):
        return int(expr)
    # Common scientific notation: 1e18, 1e15
    m = re.fullmatch(r"(\d+)e(\d+)", expr.replace(" ", ""))
    if m:
        return int(m.group(1)) * (10 ** int(m.group(2)))
    # "1 ether"
    if expr.endswith("ether"):
        try:
            num = float(expr[:-5].strip())
            return int(num * 10 ** 18)
        except ValueError:
            pass
    return None


def prune_unprofitable(
    sequences: Iterable[TransactionSequence],
    gas_price_wei: int = 30_000_000_000,   # 30 gwei conservative default
    min_margin_wei: int = 0,
) -> tuple[list[TransactionSequence], list[TransactionSequence]]:
    """
    Split sequences into (kept, pruned).

    A sequence is pruned when its ``estimated_profit_wei`` (or a value
    parsable from ``profit_estimate.min_profit_expression``) is less than
    ``gas_price_wei * total_gas_estimate + min_margin_wei``.

    Sequences whose profit can't be parsed numerically are KEPT — the
    simulator can decide. Pruning here is meant for unambiguous losers.
    """
    kept: list[TransactionSequence] = []
    pruned: list[TransactionSequence] = []
    for seq in sequences:
        profit = _profit_wei_from_estimate(seq)
        cost = gas_price_wei * max(seq.total_gas_estimate, _BASE_TX_GAS)
        if profit is None:
            kept.append(seq)
            continue
        if profit < cost + min_margin_wei:
            seq.status = SequenceStatus.REJECTED
            seq.auditor_notes.append(
                f"Pruned: estimated profit {profit:_} wei < gas cost {cost:_} wei "
                f"(@ {gas_price_wei // 10**9} gwei × {seq.total_gas_estimate:_} gas)."
            )
            pruned.append(seq)
        else:
            seq.estimated_profit_wei = profit
            kept.append(seq)
    return kept, pruned
