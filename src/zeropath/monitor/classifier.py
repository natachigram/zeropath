"""
Lightweight tx classifier — Phase 10.

The classifier sits on the latency-sensitive hot path: it must turn a raw
JSON-RPC pending-tx payload into a typed :class:`MempoolTx` and pull out
the fields the matcher cares about (selector + amount magnitudes).

No ABI decoding is performed unless the selector matches a known function;
the cost of full ABI decode per pending tx is too high for a watchtower
scanning the full mempool.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from zeropath.monitor.models import MempoolSource, MempoolTx

logger = logging.getLogger(__name__)


def _hex_to_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    s = value.lower()
    if s.startswith("0x"):
        s = s[2:]
    if not s:
        return 0
    try:
        return int(s, 16)
    except ValueError:
        return None


def _normalise_address(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    s = value.lower()
    if s.startswith("0x") and len(s) == 42:
        return s
    return None


def _extract_selector(input_hex: str) -> Optional[str]:
    if not input_hex:
        return None
    s = input_hex.lower()
    if not s.startswith("0x"):
        s = "0x" + s
    if len(s) < 10:    # 0x + 4 bytes
        return None
    return s[:10]


class TxClassifier:
    """
    Decode a raw JSON-RPC pending-tx dict into :class:`MempoolTx`.

    Resilient to missing / malformed fields — returns None for unparseable
    payloads so the orchestrator can skip without raising.
    """

    def __init__(
        self,
        *,
        chain_id: int = 1,
        source: MempoolSource = MempoolSource.JSON_RPC_POLL,
    ) -> None:
        self.chain_id = chain_id
        self.source = source

    def classify(self, raw: dict[str, Any]) -> Optional[MempoolTx]:
        """
        Parameters
        ----------
        raw : dict
            JSON-RPC ``eth_getTransactionByHash`` / pending-tx subscription
            payload. Expected keys (any may be missing/None):
              hash, from, to, value, input, nonce, gas, gasPrice,
              maxFeePerGas, maxPriorityFeePerGas, chainId.
        """
        if not isinstance(raw, dict):
            return None

        tx_hash = raw.get("hash") or raw.get("transactionHash") or ""
        if not isinstance(tx_hash, str):
            return None

        input_hex = raw.get("input") or raw.get("data") or "0x"
        if not isinstance(input_hex, str):
            input_hex = "0x"

        return MempoolTx(
            tx_hash=tx_hash.lower() if tx_hash else "",
            chain_id=_hex_to_int(raw.get("chainId")) or self.chain_id,
            from_address=_normalise_address(raw.get("from")) or "",
            to_address=_normalise_address(raw.get("to")),
            value_wei=_hex_to_int(raw.get("value")) or 0,
            input_hex=input_hex.lower() if input_hex.startswith("0x") else "0x" + input_hex.lower(),
            function_selector=_extract_selector(input_hex),
            nonce=_hex_to_int(raw.get("nonce")),
            gas_limit=_hex_to_int(raw.get("gas")),
            gas_price_wei=_hex_to_int(raw.get("gasPrice")),
            max_fee_per_gas_wei=_hex_to_int(raw.get("maxFeePerGas")),
            max_priority_fee_per_gas_wei=_hex_to_int(raw.get("maxPriorityFeePerGas")),
            source=self.source,
        )

    def classify_many(self, raws: list[dict[str, Any]]) -> list[MempoolTx]:
        out: list[MempoolTx] = []
        for r in raws:
            tx = self.classify(r)
            if tx is not None:
                out.append(tx)
        return out
