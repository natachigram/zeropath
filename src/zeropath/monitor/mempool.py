"""
Mempool subscriber — Phase 10.

Spec (phases.md, PHASE 10 Integration):
    "Subscribe to mempool via WebSocket (Alchemy, Infura, or local node)"

Two backends, sharing the same iterator interface:

  * :class:`JsonRpcPollingSubscriber` — default; uses the existing
    ``requests`` dependency to call ``eth_getBlockByNumber("pending", true)``
    on a configurable interval. Works against any RPC endpoint.

  * :class:`WebSocketSubscriber` — optional, lit up only when the
    ``websockets`` package is importable. Calls ``eth_subscribe(["newPending
    Transactions"])`` and yields each tx hash as it arrives, then fetches
    the full body via JSON-RPC.

Both yield raw dicts; the :class:`TxClassifier` converts them into
:class:`MempoolTx`.

A third :class:`SyntheticSubscriber` lets tests + replay sessions push
pre-canned transaction lists through the pipeline with no I/O at all.
"""

from __future__ import annotations

import logging
import os
import time
from abc import ABC, abstractmethod
from typing import Any, Iterable, Iterator, Optional

import requests

logger = logging.getLogger(__name__)


# Public RPC fallbacks (no API key required). Useful for smoke tests but
# rate-limited and lossy — production users should pass their own ``rpc_url``.
_PUBLIC_RPCS = {
    1:     "https://eth.llamarpc.com",
    10:    "https://mainnet.optimism.io",
    137:   "https://polygon-rpc.com",
    42161: "https://arb1.arbitrum.io/rpc",
    8453:  "https://mainnet.base.org",
}


class MempoolError(RuntimeError):
    """Wraps transport errors so callers can branch cleanly."""


# ---------------------------------------------------------------------------
# Base interface
# ---------------------------------------------------------------------------


class BaseSubscriber(ABC):
    """
    Iterable producer of raw pending-tx dicts.

    Subclasses implement :meth:`iter_transactions` as a generator that
    yields one dict per pending tx and exits when the caller calls
    :meth:`stop` (or naturally for finite sources).
    """

    def __init__(self, *, chain_id: int = 1, max_seen_cache: int = 50_000) -> None:
        self.chain_id = chain_id
        self._stop = False
        self._seen: set[str] = set()
        self._max_seen_cache = max_seen_cache

    @abstractmethod
    def iter_transactions(self) -> Iterator[dict[str, Any]]: ...

    def stop(self) -> None:
        self._stop = True

    # ------------------------------------------------------------------

    def _remember(self, tx_hash: str) -> bool:
        """Return True if this hash hasn't been seen yet (and caches it)."""
        if not tx_hash:
            return False
        if tx_hash in self._seen:
            return False
        self._seen.add(tx_hash)
        # Bound cache size to avoid unbounded memory growth.
        if len(self._seen) > self._max_seen_cache:
            # Drop ~10% of oldest entries (set ordering is insertion-order
            # in CPython 3.7+, so popping works).
            for _ in range(self._max_seen_cache // 10):
                self._seen.pop()
        return True


# ---------------------------------------------------------------------------
# JSON-RPC polling
# ---------------------------------------------------------------------------


class JsonRpcPollingSubscriber(BaseSubscriber):
    """
    Poll ``eth_getBlockByNumber("pending", true)`` at a fixed interval.

    Each poll returns the *current* pending block; we de-duplicate by tx
    hash so consumers only see each pending tx once.

    Parameters
    ----------
    rpc_url : str | None
        RPC endpoint. ``None`` falls back to ``ETH_RPC_URL`` env var, then
        to a public LlamaRPC gateway keyed on ``chain_id``.
    poll_interval_seconds : float
        How long to sleep between polls. Mainnet block time is ~12s so 4s
        gives a good probability of catching every pending tx without
        hammering the RPC.
    timeout : int
        Per-request timeout in seconds.
    """

    def __init__(
        self,
        *,
        rpc_url: Optional[str] = None,
        chain_id: int = 1,
        poll_interval_seconds: float = 4.0,
        timeout: int = 8,
    ) -> None:
        super().__init__(chain_id=chain_id)
        self.rpc_url = rpc_url or os.environ.get("ETH_RPC_URL") or _PUBLIC_RPCS.get(chain_id)
        if not self.rpc_url:
            raise MempoolError(
                f"no RPC URL for chain_id={chain_id}; set ETH_RPC_URL or pass rpc_url"
            )
        self.poll_interval = poll_interval_seconds
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})
        self._rpc_id = 0

    # ------------------------------------------------------------------

    def iter_transactions(self) -> Iterator[dict[str, Any]]:
        while not self._stop:
            try:
                block = self._rpc("eth_getBlockByNumber", ["pending", True])
            except MempoolError as exc:
                logger.warning("pending block fetch failed: %s", exc)
                time.sleep(self.poll_interval)
                continue
            if not block:
                time.sleep(self.poll_interval)
                continue
            for tx in block.get("transactions", []) or []:
                tx_hash = (tx.get("hash") or "").lower()
                if not self._remember(tx_hash):
                    continue
                yield tx
            time.sleep(self.poll_interval)

    # ------------------------------------------------------------------

    def _rpc(self, method: str, params: list[Any]) -> Any:
        self._rpc_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._rpc_id,
            "method": method,
            "params": params,
        }
        try:
            resp = self._session.post(self.rpc_url, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            body = resp.json()
        except (requests.RequestException, ValueError) as exc:
            raise MempoolError(f"{method} transport error: {exc}") from exc
        if "error" in body:
            raise MempoolError(f"{method} RPC error: {body['error']}")
        return body.get("result")


# ---------------------------------------------------------------------------
# WebSocket (optional — needs `websockets` package)
# ---------------------------------------------------------------------------


class WebSocketSubscriber(BaseSubscriber):
    """
    Subscribe via ``eth_subscribe(["newPendingTransactions"])``.

    Activated only when the ``websockets`` package is importable. If not,
    the constructor raises :class:`MempoolError`; the orchestrator catches
    and falls back to polling.
    """

    def __init__(
        self,
        *,
        ws_url: str,
        chain_id: int = 1,
        rpc_url: Optional[str] = None,
        timeout: int = 8,
    ) -> None:
        super().__init__(chain_id=chain_id)
        try:
            import websockets  # type: ignore # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise MempoolError(
                "websockets package not installed; pip install websockets"
            ) from exc
        self.ws_url = ws_url
        self.rpc_url = rpc_url or _PUBLIC_RPCS.get(chain_id)
        self.timeout = timeout
        self._session = requests.Session()

    def iter_transactions(self) -> Iterator[dict[str, Any]]:
        """
        Synchronous wrapper around an asyncio websocket loop. Yields one
        raw tx dict per pending transaction.
        """
        import asyncio
        import json
        import websockets  # type: ignore

        async def _stream():
            async with websockets.connect(self.ws_url, ping_interval=20) as ws:
                await ws.send(json.dumps({
                    "jsonrpc": "2.0", "id": 1,
                    "method": "eth_subscribe",
                    "params": ["newPendingTransactions"],
                }))
                # First message is subscription confirmation.
                await ws.recv()
                while not self._stop:
                    msg = await ws.recv()
                    data = json.loads(msg)
                    tx_hash = (
                        data.get("params", {}).get("result", "")
                        if isinstance(data.get("params"), dict) else ""
                    )
                    if not isinstance(tx_hash, str):
                        continue
                    if not self._remember(tx_hash.lower()):
                        continue
                    raw = self._fetch_tx(tx_hash)
                    if raw:
                        yield raw

        loop = asyncio.new_event_loop()
        try:
            async_gen = _stream().__aiter__()
            while not self._stop:
                try:
                    tx = loop.run_until_complete(async_gen.__anext__())
                except StopAsyncIteration:
                    break
                yield tx
        finally:
            loop.close()

    def _fetch_tx(self, tx_hash: str) -> Optional[dict[str, Any]]:
        if not self.rpc_url:
            return None
        try:
            resp = self._session.post(
                self.rpc_url,
                json={
                    "jsonrpc": "2.0", "id": 1,
                    "method": "eth_getTransactionByHash",
                    "params": [tx_hash],
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return resp.json().get("result")
        except (requests.RequestException, ValueError):
            return None


# ---------------------------------------------------------------------------
# Synthetic (tests / replay)
# ---------------------------------------------------------------------------


class SyntheticSubscriber(BaseSubscriber):
    """
    Yields pre-canned tx dicts. Useful for tests, replay scenarios, and
    smoke runs where touching a real RPC isn't desirable.
    """

    def __init__(
        self,
        txs: Iterable[dict[str, Any]],
        *,
        chain_id: int = 1,
        loop: bool = False,
    ) -> None:
        super().__init__(chain_id=chain_id)
        self._txs = list(txs)
        self.loop = loop

    def iter_transactions(self) -> Iterator[dict[str, Any]]:
        while not self._stop:
            for tx in self._txs:
                if self._stop:
                    return
                yield tx
            if not self.loop:
                return
