"""
Anvil process controller + JSON-RPC client — Phase 5.

Spec (phases.md, PHASE 5):
    "Use Foundry (forge + anvil). Foundry is Rust — interface via Anvil
     JSON-RPC. Python orchestrates via web3.py against the Anvil RPC
     endpoint."

This module wraps `anvil` as a subprocess and exposes a small JSON-RPC client
(``requests``-based) plus the Anvil-specific cheat codes we need from Python:

  * ``anvil_impersonateAccount`` / ``anvil_stopImpersonatingAccount``
  * ``anvil_setBalance``, ``anvil_setCode``, ``anvil_setStorageAt``
  * ``anvil_snapshot`` / ``anvil_revert`` (reproducibility)
  * ``anvil_mine``

Lifecycle::

    with AnvilProcess(fork_url=..., fork_block=18_000_000) as anvil:
        anvil.set_balance(attacker, 100 * 10**18)
        snap = anvil.snapshot()
        tx = anvil.send_transaction({...})
        anvil.revert_to(snap)

The context manager guarantees the subprocess is reaped even on exceptions.
If ``anvil`` is not on PATH the constructor raises :class:`AnvilNotAvailable`
so callers can degrade gracefully (Phase 5 orchestrator skips execution and
returns ``SimulationOutcome.NOT_EXECUTED``).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import subprocess
import time
from typing import Any, Iterable, Optional

import requests

logger = logging.getLogger(__name__)


class AnvilError(Exception):
    """JSON-RPC call against the Anvil endpoint failed."""


class AnvilNotAvailable(AnvilError):
    """``anvil`` binary not found on PATH."""


def _free_port() -> int:
    """Reserve and immediately release a TCP port to avoid races."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class AnvilProcess:
    """
    Manage an Anvil subprocess and speak to it over JSON-RPC.

    Parameters
    ----------
    fork_url : str | None
        Upstream RPC to fork from. ``None`` runs in pure-EVM mode (no fork).
    fork_block : int | None
        Block to fork at. ``None`` → upstream latest.
    chain_id : int
        Chain ID exposed to contracts. Default 1 (Ethereum mainnet).
    port : int | None
        TCP port for the Anvil RPC. ``None`` reserves a free port.
    binary : str
        Path or PATH-name of the ``anvil`` executable.
    extra_args : list[str] | None
        Additional CLI args appended verbatim.
    startup_timeout : float
        Seconds to wait for the RPC to become responsive.
    """

    def __init__(
        self,
        *,
        fork_url: Optional[str] = None,
        fork_block: Optional[int] = None,
        chain_id: int = 1,
        port: Optional[int] = None,
        binary: str = "anvil",
        extra_args: Optional[list[str]] = None,
        startup_timeout: float = 10.0,
    ) -> None:
        if shutil.which(binary) is None:
            raise AnvilNotAvailable(
                f"`{binary}` not found on PATH — install Foundry "
                f"(https://book.getfoundry.sh/getting-started/installation)"
            )
        self.binary = binary
        self.fork_url = fork_url
        self.fork_block = fork_block
        self.chain_id = chain_id
        self.port = port or _free_port()
        self.extra_args = list(extra_args or [])
        self.startup_timeout = startup_timeout

        self._proc: Optional[subprocess.Popen] = None
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})
        self._rpc_id = 0
        self._anvil_version: str = ""

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        if self._proc is not None:
            return
        args = [
            self.binary,
            "--port", str(self.port),
            "--host", "127.0.0.1",
            "--chain-id", str(self.chain_id),
            "--silent",
        ]
        if self.fork_url:
            args += ["--fork-url", self.fork_url]
        if self.fork_block is not None:
            args += ["--fork-block-number", str(self.fork_block)]
        args += self.extra_args

        logger.info("Spawning anvil on port %d (fork=%s @ %s)",
                    self.port, bool(self.fork_url), self.fork_block)
        self._proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ},
        )
        self._wait_until_ready()
        try:
            self._anvil_version = self._rpc("web3_clientVersion", []) or ""
        except AnvilError:
            self._anvil_version = ""

    def stop(self) -> None:
        if self._proc is None:
            return
        try:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=2)
        finally:
            self._proc = None

    def __enter__(self) -> "AnvilProcess":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + self.startup_timeout
        last_err: Optional[Exception] = None
        while time.monotonic() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                # Process died during startup — surface stderr for debugging.
                err = self._proc.stderr.read().decode("utf-8", errors="replace") if self._proc.stderr else ""
                raise AnvilError(f"anvil exited during startup: {err.strip() or self._proc.returncode}")
            try:
                resp = self._session.post(
                    self.url,
                    json={"jsonrpc": "2.0", "id": 0, "method": "web3_clientVersion", "params": []},
                    timeout=0.5,
                )
                if resp.ok and "result" in resp.json():
                    return
            except (requests.RequestException, ValueError) as exc:
                last_err = exc
            time.sleep(0.1)
        raise AnvilError(f"anvil did not become ready within {self.startup_timeout}s: {last_err}")

    # ------------------------------------------------------------------
    # JSON-RPC primitive
    # ------------------------------------------------------------------

    def _rpc(self, method: str, params: list[Any]) -> Any:
        if self._proc is None or self._proc.poll() is not None:
            raise AnvilError("anvil process is not running")
        self._rpc_id += 1
        payload = {"jsonrpc": "2.0", "id": self._rpc_id, "method": method, "params": params}
        try:
            resp = self._session.post(self.url, json=payload, timeout=15)
            resp.raise_for_status()
            body = resp.json()
        except (requests.RequestException, ValueError) as exc:
            raise AnvilError(f"{method} transport error: {exc}") from exc
        if "error" in body:
            err = body["error"]
            raise AnvilError(f"{method} RPC error: {err.get('message', err)}")
        return body.get("result")

    def call(self, method: str, params: Iterable[Any] = ()) -> Any:
        """Public wrapper around the JSON-RPC primitive (errors → AnvilError)."""
        return self._rpc(method, list(params))

    # ------------------------------------------------------------------
    # Standard read-only RPC
    # ------------------------------------------------------------------

    def chain_id_rpc(self) -> int:
        return int(self._rpc("eth_chainId", []), 16)

    def block_number(self) -> int:
        return int(self._rpc("eth_blockNumber", []), 16)

    def get_balance(self, address: str, block: str = "latest") -> int:
        return int(self._rpc("eth_getBalance", [address, block]), 16)

    def get_storage_at(self, address: str, slot: str, block: str = "latest") -> str:
        return self._rpc("eth_getStorageAt", [address, slot, block])

    def eth_call(self, to: str, data_hex: str, block: str = "latest") -> str:
        return self._rpc("eth_call", [{"to": to, "data": data_hex}, block])

    # ------------------------------------------------------------------
    # Transaction submission
    # ------------------------------------------------------------------

    def send_transaction(self, tx: dict[str, Any]) -> str:
        """Submit a tx (anvil signs with the impersonated/unlocked sender)."""
        return self._rpc("eth_sendTransaction", [tx])

    def get_transaction_receipt(self, tx_hash: str) -> Optional[dict[str, Any]]:
        return self._rpc("eth_getTransactionReceipt", [tx_hash])

    # ------------------------------------------------------------------
    # Anvil cheat codes
    # ------------------------------------------------------------------

    def impersonate(self, account: str) -> None:
        self._rpc("anvil_impersonateAccount", [account])

    def stop_impersonate(self, account: str) -> None:
        self._rpc("anvil_stopImpersonatingAccount", [account])

    def set_balance(self, account: str, wei: int) -> None:
        self._rpc("anvil_setBalance", [account, hex(wei)])

    def set_code(self, account: str, code_hex: str) -> None:
        self._rpc("anvil_setCode", [account, code_hex])

    def set_storage_at(self, account: str, slot: str, value: str) -> None:
        self._rpc("anvil_setStorageAt", [account, slot, value])

    def snapshot(self) -> str:
        return self._rpc("evm_snapshot", [])

    def revert_to(self, snap_id: str) -> bool:
        return bool(self._rpc("evm_revert", [snap_id]))

    def mine(self, count: int = 1) -> None:
        self._rpc("anvil_mine", [hex(count)])

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @property
    def anvil_version(self) -> str:
        return self._anvil_version

    def is_alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @staticmethod
    def scrub_url(url: str) -> str:
        """Redact API keys before persisting an RPC URL."""
        for marker in ("/v2/", "/v3/", "?apikey=", "?api-key=", "?key="):
            idx = url.find(marker)
            if idx > 0:
                return url[: idx + len(marker)] + "<redacted>"
        return url.split("?")[0]
