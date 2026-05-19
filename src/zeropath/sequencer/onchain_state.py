"""
Live on-chain state fetcher — Phase 4.

Resolves the *real* mainnet state required to make a generated transaction
sequence executable on a Foundry fork:

  * pool reserves   (UniV2 ``getReserves``, UniV3 ``slot0``)
  * oracle prices   (Chainlink ``latestRoundData``)
  * token balances  (ERC-20 ``balanceOf`` / ``totalSupply``)
  * ETH balances    (eth_getBalance)
  * raw storage     (eth_getStorageAt)

Speaks JSON-RPC directly via ``requests`` to avoid a hard ``web3.py`` /
``eth-abi`` dependency. Calls ``eth_call`` with ABI-encoded calldata from
``sequencer.abi_encoder``.

Spec (phases.md, PHASE 4 critical additions):
    "Integrate with an Ethereum RPC (Alchemy, Infura, or local node) to
     fetch live state before sequence generation."
"""

from __future__ import annotations

import logging
import os
import time
from typing import Optional

import requests

from zeropath.sequencer.abi_encoder import encode_call
from zeropath.sequencer.models import OnChainStateSnapshot

logger = logging.getLogger(__name__)


# Canonical mainnet addresses for common protocols/tokens
_PUBLIC_RPCS = {
    1:     "https://eth.llamarpc.com",
    10:    "https://mainnet.optimism.io",
    137:   "https://polygon-rpc.com",
    42161: "https://arb1.arbitrum.io/rpc",
    8453:  "https://mainnet.base.org",
}

_CHAIN_NAME_TO_ID = {
    "mainnet":  1,
    "ethereum": 1,
    "optimism": 10,
    "polygon":  137,
    "arbitrum": 42161,
    "base":     8453,
}


class OnChainStateError(Exception):
    """JSON-RPC call failed or returned malformed data."""


class OnChainStateFetcher:
    """
    Fetch live mainnet state at a specific block.

    Designed to be a *best-effort* layer: if the RPC is unreachable or a
    specific call fails, the fetcher returns whatever it was able to collect
    and logs the failure. Builders must tolerate a partial snapshot.

    Args:
        rpc_url:   RPC endpoint. If None, reads ``ETH_RPC_URL`` from env,
                   falling back to a public llamarpc gateway.
        chain:     Chain name or numeric chain ID.
        timeout:   Per-request timeout in seconds.
    """

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        chain: str | int = "mainnet",
        timeout: int = 10,
    ) -> None:
        self.chain_id = self._resolve_chain(chain)
        self.rpc_url = rpc_url or os.environ.get("ETH_RPC_URL") or _PUBLIC_RPCS.get(self.chain_id)
        if not self.rpc_url:
            raise OnChainStateError(
                f"No RPC URL available for chain_id={self.chain_id}. "
                f"Set ETH_RPC_URL or pass rpc_url explicitly."
            )
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})
        self._request_id = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch_snapshot(
        self,
        *,
        block_number: Optional[int] = None,
        pools: list[str] | None = None,
        oracles: list[str] | None = None,
        token_balances: list[tuple[str, str]] | None = None,
        eth_balances: list[str] | None = None,
        tokens_for_metadata: list[str] | None = None,
    ) -> OnChainStateSnapshot:
        """
        Fetch a complete state snapshot for a set of addresses.

        ``block_number=None`` resolves to "latest"; everything that follows
        is pinned to the same block for consistency.
        """
        if block_number is None:
            block_number = self._latest_block()
        block_hex = hex(block_number)
        timestamp = self._block_timestamp(block_hex)

        snapshot = OnChainStateSnapshot(
            block_number=block_number,
            block_timestamp=timestamp,
            chain_id=self.chain_id,
            rpc_provider=self._scrubbed_rpc(),
            fetched_at_unix=int(time.time()),
        )

        for pool in pools or []:
            r = self._safe_get_reserves(pool, block_hex)
            if r is not None:
                snapshot.pool_reserves[pool.lower()] = r

        for oracle in oracles or []:
            o = self._safe_get_chainlink_price(oracle, block_hex)
            if o is not None:
                snapshot.oracle_prices[oracle.lower()] = o

        for token, holder in token_balances or []:
            bal = self._safe_erc20_balance_of(token, holder, block_hex)
            if bal is not None:
                snapshot.token_balances[f"{token.lower()}:{holder.lower()}"] = bal

        for addr in eth_balances or []:
            eb = self._safe_eth_balance(addr, block_hex)
            if eb is not None:
                snapshot.eth_balances[addr.lower()] = eb

        for token in tokens_for_metadata or []:
            meta = self._safe_token_metadata(token, block_hex)
            if meta:
                snapshot.token_metadata[token.lower()] = meta

        logger.info(
            "OnChainStateFetcher snapshot @block=%d: %d pools, %d oracles, "
            "%d token balances, %d eth balances",
            block_number, len(snapshot.pool_reserves),
            len(snapshot.oracle_prices), len(snapshot.token_balances),
            len(snapshot.eth_balances),
        )
        return snapshot

    # ------------------------------------------------------------------
    # Targeted helpers (also usable standalone by builders)
    # ------------------------------------------------------------------

    def _safe_get_reserves(
        self, pool: str, block: str
    ) -> tuple[int, int, int] | None:
        """UniV2 IUniswapV2Pair.getReserves(): (uint112, uint112, uint32)."""
        try:
            data = encode_call("getReserves()", [])
            result = self._eth_call(pool, "0x" + data.hex(), block)
            if not result or result == "0x":
                return None
            raw = bytes.fromhex(result[2:])
            if len(raw) < 96:
                return None
            r0 = int.from_bytes(raw[0:32], "big")
            r1 = int.from_bytes(raw[32:64], "big")
            ts = int.from_bytes(raw[64:96], "big")
            return (r0, r1, ts)
        except Exception as exc:
            logger.debug("getReserves failed for %s: %s", pool, exc)
            return None

    def _safe_get_chainlink_price(
        self, aggregator: str, block: str
    ) -> tuple[int, int, int] | None:
        """
        Chainlink AggregatorV3Interface.latestRoundData() returns
        (uint80, int256, uint256, uint256, uint80). We capture (price,
        decimals, updatedAt).
        """
        try:
            data = encode_call("latestRoundData()", [])
            result = self._eth_call(aggregator, "0x" + data.hex(), block)
            if not result or result == "0x":
                return None
            raw = bytes.fromhex(result[2:])
            if len(raw) < 160:
                return None
            price = int.from_bytes(raw[32:64], "big", signed=True)
            updated_at = int.from_bytes(raw[96:128], "big")

            # Fetch decimals() separately — most Chainlink aggregators expose it.
            dec_data = encode_call("decimals()", [])
            dec_res = self._eth_call(aggregator, "0x" + dec_data.hex(), block)
            decimals = int(dec_res, 16) if dec_res and dec_res != "0x" else 8
            return (price, decimals, updated_at)
        except Exception as exc:
            logger.debug("Chainlink price failed for %s: %s", aggregator, exc)
            return None

    def _safe_erc20_balance_of(
        self, token: str, holder: str, block: str
    ) -> int | None:
        try:
            data = encode_call("balanceOf(address)", [holder])
            result = self._eth_call(token, "0x" + data.hex(), block)
            if not result or result == "0x":
                return None
            return int(result, 16)
        except Exception as exc:
            logger.debug("balanceOf failed for %s @ %s: %s", token, holder, exc)
            return None

    def _safe_eth_balance(self, addr: str, block: str) -> int | None:
        try:
            result = self._rpc("eth_getBalance", [addr, block])
            return int(result, 16) if result else None
        except Exception as exc:
            logger.debug("eth_getBalance failed for %s: %s", addr, exc)
            return None

    def _safe_token_metadata(self, token: str, block: str) -> dict:
        meta: dict = {}
        for sig, key in (
            ("symbol()", "symbol"),
            ("decimals()", "decimals"),
            ("totalSupply()", "totalSupply"),
        ):
            try:
                data = encode_call(sig, [])
                result = self._eth_call(token, "0x" + data.hex(), block)
                if not result or result == "0x":
                    continue
                if key == "symbol":
                    meta[key] = self._decode_string(result)
                else:
                    meta[key] = int(result, 16)
            except Exception:
                pass
        return meta

    # ------------------------------------------------------------------
    # JSON-RPC plumbing
    # ------------------------------------------------------------------

    def _eth_call(self, to: str, data_hex: str, block: str) -> str | None:
        return self._rpc("eth_call", [{"to": to, "data": data_hex}, block])

    def _latest_block(self) -> int:
        result = self._rpc("eth_blockNumber", [])
        if result is None:
            raise OnChainStateError("eth_blockNumber returned no result")
        return int(result, 16)

    def _block_timestamp(self, block_hex: str) -> int | None:
        try:
            block = self._rpc("eth_getBlockByNumber", [block_hex, False])
            return int(block["timestamp"], 16) if block else None
        except Exception as exc:
            logger.debug("eth_getBlockByNumber failed: %s", exc)
            return None

    def _rpc(self, method: str, params: list):
        self._request_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params,
        }
        try:
            resp = self._session.post(self.rpc_url, json=payload, timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise OnChainStateError(f"RPC {method} transport error: {exc}") from exc
        body = resp.json()
        if "error" in body:
            raise OnChainStateError(f"RPC {method} error: {body['error']}")
        return body.get("result")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_string(hex_result: str) -> str:
        """Decode an ABI-encoded ``string`` return value, falling back to bytes32."""
        try:
            raw = bytes.fromhex(hex_result[2:])
            if len(raw) >= 64:
                length = int.from_bytes(raw[32:64], "big")
                if 0 < length <= 256 and 64 + length <= len(raw):
                    return raw[64:64 + length].decode("utf-8", errors="replace")
            # bytes32-style return (some old tokens like MKR)
            return raw[:32].rstrip(b"\x00").decode("utf-8", errors="replace")
        except Exception:
            return ""

    @staticmethod
    def _resolve_chain(chain: str | int) -> int:
        if isinstance(chain, int):
            return chain
        if isinstance(chain, str) and chain.isdigit():
            return int(chain)
        cid = _CHAIN_NAME_TO_ID.get(chain.lower() if isinstance(chain, str) else "")
        if cid is None:
            raise OnChainStateError(f"unknown chain: {chain!r}")
        return cid

    def _scrubbed_rpc(self) -> str:
        """Strip API keys from RPC URLs before logging or persisting."""
        url = self.rpc_url or ""
        for marker in ("/v2/", "/v3/", "?apikey=", "?api-key=", "?key="):
            idx = url.find(marker)
            if idx > 0:
                return url[: idx + len(marker)] + "<redacted>"
        return url.split("?")[0]
