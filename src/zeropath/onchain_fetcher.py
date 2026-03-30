"""
On-chain contract source fetcher.

Resolves a contract address + chain to local source files (or bytecode)
using a three-tier fallback strategy:

  Tier 1 — Etherscan-compatible block explorer APIs
            Covers mainnet, Polygon, Arbitrum, Optimism, Base, BSC,
            Avalanche, Gnosis, Fantom, and more via their native Etherscan
            clones. Requires an API key for sustained use.

  Tier 2 — Sourcify (https://sourcify.dev)
            Decentralised, no API key required.  Partial matches are
            accepted (source may not be exactly as deployed).

  Tier 3 — Bytecode only (via JSON-RPC eth_getCode)
            Falls back when no verified source is available anywhere.
            The caller should then route to HeimdallDecompiler.

All HTTP calls use a configurable timeout and produce structured logging.
"""

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

import requests

from zeropath.exceptions import ZeropathError
from zeropath.logging_config import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Chain registry
# ---------------------------------------------------------------------------

#: Map of common chain names / aliases → EIP-155 chain IDs
CHAIN_IDS: dict[str, int] = {
    # Ethereum
    "mainnet": 1,
    "ethereum": 1,
    "eth": 1,
    "homestead": 1,
    # Layer 2 & side chains
    "polygon": 137,
    "matic": 137,
    "arbitrum": 42161,
    "arbitrum-one": 42161,
    "arb": 42161,
    "optimism": 10,
    "op": 10,
    "base": 8453,
    "zksync": 324,
    "zksync-era": 324,
    "linea": 59144,
    "scroll": 534352,
    "polygon-zkevm": 1101,
    "mantle": 5000,
    # BSC / Avalanche / Fantom
    "bsc": 56,
    "binance": 56,
    "bnb": 56,
    "avalanche": 43114,
    "avax": 43114,
    "fantom": 250,
    "ftm": 250,
    # Other
    "gnosis": 100,
    "xdai": 100,
    "aurora": 1313161554,
    "celo": 42220,
    "moonbeam": 1284,
    "cronos": 25,
    # Test nets
    "sepolia": 11155111,
    "goerli": 5,
    "mumbai": 80001,
    "arbitrum-goerli": 421613,
    "optimism-goerli": 420,
    "base-goerli": 84531,
}

#: Etherscan-compatible API base URLs keyed by chain ID
ETHERSCAN_APIS: dict[int, str] = {
    1: "https://api.etherscan.io/api",
    137: "https://api.polygonscan.com/api",
    42161: "https://api.arbiscan.io/api",
    10: "https://api-optimistic.etherscan.io/api",
    8453: "https://api.basescan.org/api",
    56: "https://api.bscscan.com/api",
    43114: "https://api.snowtrace.io/api",
    250: "https://api.ftmscan.com/api",
    100: "https://api.gnosisscan.io/api",
    324: "https://api-era.zksync.network/api",
    59144: "https://api.lineascan.build/api",
    534352: "https://api.scrollscan.com/api",
    25: "https://api.cronoscan.com/api",
    42220: "https://api.celoscan.io/api",
    1284: "https://api-moonbeam.moonscan.io/api",
    11155111: "https://api-sepolia.etherscan.io/api",
    5: "https://api-goerli.etherscan.io/api",
    80001: "https://api-testnet.polygonscan.com/api",
}

#: Publicly accessible JSON-RPC endpoints (no auth, rate-limited)
PUBLIC_RPC_URLS: dict[int, str] = {
    1: "https://ethereum.rpc.subquery.network/public",
    137: "https://polygon.rpc.subquery.network/public",
    42161: "https://arbitrum.rpc.subquery.network/public",
    10: "https://optimism.rpc.subquery.network/public",
    8453: "https://base.rpc.subquery.network/public",
    56: "https://bsc.rpc.subquery.network/public",
    43114: "https://avalanche.rpc.subquery.network/public",
    250: "https://fantom.rpc.subquery.network/public",
    100: "https://gnosis.rpc.subquery.network/public",
}

#: Sourcify API base URL
SOURCIFY_API = "https://sourcify.dev/server"


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class OnChainSource:
    """
    Everything retrieved for a given contract address from on-chain sources.

    If source_available is True, source_files contains the full contract
    source keyed by filename.  If False, bytecode is set and the caller
    should route to HeimdallDecompiler.
    """

    address: str
    chain_id: int
    chain_name: str
    contract_name: str
    compiler_version: Optional[str]
    source_files: dict[str, str]  # filename → Solidity / Vyper source
    source_available: bool
    bytecode: Optional[str]  # raw hex when source_available=False
    abi: Optional[list[dict[str, Any]]]
    fetch_tier: str  # "etherscan" | "sourcify" | "bytecode_only"


# ---------------------------------------------------------------------------
# Fetcher
# ---------------------------------------------------------------------------


class OnChainFetcher:
    """
    Resolve a contract address + chain to local source files.

    Args:
        etherscan_api_key: Block-explorer API key.  Without it Etherscan
                           still works but is rate-limited to 1 req/5 s.
        rpc_url:           Override the public RPC endpoint.
        timeout:           HTTP request timeout in seconds.
    """

    def __init__(
        self,
        etherscan_api_key: Optional[str] = None,
        rpc_url: Optional[str] = None,
        timeout: int = 30,
    ) -> None:
        self._api_key = etherscan_api_key
        self._rpc_url = rpc_url
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "ZeroPath/0.2.0"})

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch(self, address: str, chain: str = "mainnet") -> OnChainSource:
        """
        Fetch verified source (or bytecode) for a contract address.

        Args:
            address: 0x-prefixed 20-byte Ethereum address.
            chain:   Chain name or numeric string chain ID.

        Returns:
            OnChainSource with source_available=True when source was found.

        Raises:
            ZeropathError: If the address format is invalid.
        """
        address = _normalise_address(address)
        chain_id = _resolve_chain(chain)
        chain_name = _chain_name(chain_id)

        logger.info(
            "onchain_fetch_start",
            address=address,
            chain=chain_name,
            chain_id=chain_id,
        )

        # Tier 1: Etherscan-compatible
        result = self._try_etherscan(address, chain_id)
        if result:
            logger.info(
                "source_found_etherscan",
                address=address,
                contract=result.contract_name,
                files=len(result.source_files),
            )
            return result

        # Tier 2: Sourcify
        result = self._try_sourcify(address, chain_id)
        if result:
            logger.info(
                "source_found_sourcify",
                address=address,
                contract=result.contract_name,
                files=len(result.source_files),
            )
            return result

        # Tier 3: Bytecode only
        logger.warning(
            "source_not_found_falling_back_to_bytecode",
            address=address,
            chain=chain_name,
        )
        bytecode = self._fetch_bytecode(address, chain_id)

        return OnChainSource(
            address=address,
            chain_id=chain_id,
            chain_name=chain_name,
            contract_name=f"Unknown_{address[:10]}",
            compiler_version=None,
            source_files={},
            source_available=False,
            bytecode=bytecode,
            abi=None,
            fetch_tier="bytecode_only",
        )

    def write_sources_to_tempdir(self, source: OnChainSource) -> Path:
        """
        Write all source files (or a .bin file for bytecode) to a temp directory.

        The returned directory is owned by the caller and must be cleaned up.

        Returns:
            Path to the directory containing .sol / .vy / .bin files.
        """
        tmpdir = Path(tempfile.mkdtemp(prefix="zeropath_onchain_"))

        if source.source_available:
            for filename, content in source.source_files.items():
                # Sanitise path (avoid path traversal)
                safe_name = Path(filename).name
                if not safe_name:
                    safe_name = f"{source.contract_name}.sol"
                dest = tmpdir / safe_name
                dest.write_text(content, encoding="utf-8")
                logger.debug("wrote_source_file", path=str(dest))
        elif source.bytecode:
            bin_file = tmpdir / f"{source.contract_name}.bin"
            bin_file.write_text(source.bytecode, encoding="utf-8")
            logger.debug("wrote_bytecode_file", path=str(bin_file))

        return tmpdir

    # ------------------------------------------------------------------
    # Tier 1 — Etherscan
    # ------------------------------------------------------------------

    def _try_etherscan(self, address: str, chain_id: int) -> Optional[OnChainSource]:
        """Fetch source from Etherscan-compatible API."""
        api_url = ETHERSCAN_APIS.get(chain_id)
        if not api_url:
            logger.debug("no_etherscan_api_for_chain", chain_id=chain_id)
            return None

        params: dict[str, str] = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
        }
        if self._api_key:
            params["apikey"] = self._api_key

        try:
            resp = self._session.get(api_url, params=params, timeout=self._timeout)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.warning("etherscan_request_failed", error=str(exc), chain_id=chain_id)
            return None

        if data.get("status") != "1" or not data.get("result"):
            return None

        entry = data["result"][0]
        source_code = entry.get("SourceCode", "").strip()
        contract_name = entry.get("ContractName", "").strip() or f"Contract_{address[:10]}"
        compiler_version = entry.get("CompilerVersion", "").strip() or None
        abi_raw = entry.get("ABI", "").strip()

        # Parse ABI
        abi: Optional[list[dict]] = None
        if abi_raw and abi_raw != "Contract source code not verified":
            try:
                abi = json.loads(abi_raw)
            except json.JSONDecodeError:
                pass

        if not source_code or source_code == "Contract source code not verified":
            return None

        source_files = _parse_etherscan_source(source_code, contract_name)

        return OnChainSource(
            address=address,
            chain_id=chain_id,
            chain_name=_chain_name(chain_id),
            contract_name=contract_name,
            compiler_version=compiler_version,
            source_files=source_files,
            source_available=True,
            bytecode=None,
            abi=abi,
            fetch_tier="etherscan",
        )

    # ------------------------------------------------------------------
    # Tier 2 — Sourcify
    # ------------------------------------------------------------------

    def _try_sourcify(self, address: str, chain_id: int) -> Optional[OnChainSource]:
        """Fetch source from Sourcify."""
        files_url = f"{SOURCIFY_API}/files/any/{chain_id}/{address}"
        try:
            resp = self._session.get(files_url, timeout=self._timeout)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.debug("sourcify_request_failed", error=str(exc), chain_id=chain_id)
            return None

        files = data.get("files", [])
        if not files:
            return None

        source_files: dict[str, str] = {}
        contract_name = f"Contract_{address[:10]}"

        for f in files:
            name: str = f.get("name", "")
            content: str = f.get("content", "")
            path: str = f.get("path", name)

            if not content:
                continue

            # Only collect .sol / .vy source files
            if path.endswith((".sol", ".vy")):
                source_files[Path(path).name] = content
                if path.endswith(".sol") and contract_name.startswith("Contract_"):
                    contract_name = Path(path).stem

        if not source_files:
            return None

        return OnChainSource(
            address=address,
            chain_id=chain_id,
            chain_name=_chain_name(chain_id),
            contract_name=contract_name,
            compiler_version=None,
            source_files=source_files,
            source_available=True,
            bytecode=None,
            abi=None,
            fetch_tier="sourcify",
        )

    # ------------------------------------------------------------------
    # Tier 3 — Bytecode via JSON-RPC
    # ------------------------------------------------------------------

    def _fetch_bytecode(self, address: str, chain_id: int) -> Optional[str]:
        """Call eth_getCode on the chain's RPC endpoint."""
        rpc_url = self._rpc_url or PUBLIC_RPC_URLS.get(chain_id)
        if not rpc_url:
            logger.warning(
                "no_rpc_url_for_chain",
                chain_id=chain_id,
                msg="Provide ZEROPATH_RPC_URL to enable bytecode fallback",
            )
            return None

        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getCode",
            "params": [address, "latest"],
        }
        try:
            resp = self._session.post(rpc_url, json=payload, timeout=self._timeout)
            resp.raise_for_status()
            result = resp.json().get("result", "0x")
            if result in ("0x", "0x0", None):
                logger.warning(
                    "eth_getcode_empty",
                    address=address,
                    msg="Address is an EOA or the contract was self-destructed",
                )
                return None
            return result
        except Exception as exc:
            logger.warning("rpc_fetch_bytecode_failed", error=str(exc), address=address)
            return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalise_address(address: str) -> str:
    """Validate and lowercase-normalise a 0x Ethereum address."""
    addr = address.strip()
    if not addr.startswith("0x") or len(addr) != 42:
        raise ZeropathError(
            f"Invalid Ethereum address: '{address}'. "
            "Expected 0x-prefixed 20-byte hex string (42 characters)."
        )
    return addr.lower()


def _resolve_chain(chain: str) -> int:
    """Map a chain name or numeric string to its chain ID."""
    # Accept numeric IDs directly
    if chain.isdigit():
        return int(chain)
    chain_id = CHAIN_IDS.get(chain.lower())
    if chain_id is None:
        raise ZeropathError(
            f"Unknown chain: '{chain}'. "
            f"Supported: {', '.join(sorted(CHAIN_IDS)[:20])} ..."
        )
    return chain_id


def _chain_name(chain_id: int) -> str:
    """Return a human-readable name for a chain ID."""
    for name, cid in CHAIN_IDS.items():
        if cid == chain_id:
            return name
    return str(chain_id)


def _parse_etherscan_source(source_code: str, contract_name: str) -> dict[str, str]:
    """
    Parse the SourceCode field from an Etherscan API response.

    Handles three formats:
    - Double-brace wrapped JSON:  ``{{...standard-json-input...}}``
    - Single-brace JSON:           ``{...}``  (some proxy implementations)
    - Plain text:                  Single-file Solidity source
    """
    stripped = source_code.strip()

    # Format 1: Etherscan wraps standard JSON input in an extra pair of braces
    if stripped.startswith("{{"):
        inner = stripped[1:-1]  # peel off the outer { and }
        try:
            data = json.loads(inner)
            return {
                Path(fname).name: src_obj.get("content", "")
                for fname, src_obj in data.get("sources", {}).items()
                if src_obj.get("content")
            }
        except json.JSONDecodeError:
            pass

    # Format 2: plain JSON — either standard-json or a sources dict
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            if "sources" in data:
                return {
                    Path(fname).name: src_obj.get("content", "")
                    for fname, src_obj in data["sources"].items()
                    if src_obj.get("content")
                }
        except json.JSONDecodeError:
            pass

    # Format 3: plain single-file source
    filename = f"{contract_name}.sol" if not contract_name.endswith(".sol") else contract_name
    return {filename: source_code}
