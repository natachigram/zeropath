"""
Proxy pattern detector for Solidity smart contracts.

Detects all major proxy patterns used in production DeFi:
  - EIP-1967 Transparent Proxy (OpenZeppelin TransparentUpgradeableProxy)
  - UUPS (ERC-1822, OpenZeppelin UUPSUpgradeable)
  - Beacon Proxy (OpenZeppelin BeaconProxy)
  - EIP-2535 Diamond Proxy (multi-facet)
  - EIP-1167 Minimal Proxy Clone
  - Custom proxies (delegatecall in fallback without standard slots)

Uses Slither's IR layer where possible. Falls back to name-based heuristics.
"""

from dataclasses import dataclass, field
from typing import Any, Optional

from zeropath.exceptions import ProxyDetectionError
from zeropath.logging_config import get_logger
from zeropath.models import ProxyRelationship, ProxyType

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# EIP-1967 storage slot constants (keccak256(...) - 1)
# ---------------------------------------------------------------------------
_IMPLEMENTATION_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
_ADMIN_SLOT = (
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
)
_BEACON_SLOT = (
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
)

# ---------------------------------------------------------------------------
# Name patterns for known proxy base contracts
# ---------------------------------------------------------------------------
_TRANSPARENT_BASES = {
    "TransparentUpgradeableProxy",
    "AdminUpgradeabilityProxy",
    "Proxy",
    "BaseAdminUpgradeabilityProxy",
}
_UUPS_BASES = {
    "UUPSUpgradeable",
    "ERC1967Upgrade",
}
_BEACON_BASES = {
    "BeaconProxy",
    "UpgradeableBeacon",
}
_DIAMOND_FUNCTIONS = {"diamondCut", "facetAddresses", "facetAddress", "facets"}
_UPGRADE_FUNCTIONS = {
    "upgradeTo",
    "upgradeToAndCall",
    "_authorizeUpgrade",
    "upgradeBeaconTo",
}

# EIP-1167 minimal proxy bytecode prefix (bytes)
_MINIMAL_PROXY_PREFIX = bytes.fromhex("363d3d373d3d3d363d73")


@dataclass
class _DetectionResult:
    proxy_type: ProxyType
    is_upgradeable: bool
    upgrade_function: Optional[str]
    admin_function: Optional[str]
    implementation_slot: Optional[str]
    evidence: list[str] = field(default_factory=list)


class ProxyDetector:
    """
    Detects proxy patterns in a Slither-parsed contract.

    Usage::

        detector = ProxyDetector()
        for contract in slither.contracts:
            result = detector.detect(contract)
            if result.proxy_type != ProxyType.NONE:
                ...
    """

    def detect(self, contract: Any) -> _DetectionResult:
        """
        Run all detection strategies on a contract and return the best match.

        Args:
            contract: A Slither Contract object.

        Returns:
            _DetectionResult with the most specific proxy type found.

        Raises:
            ProxyDetectionError: If detection itself throws an unexpected error.
        """
        try:
            strategies = [
                self._detect_slither_builtin,
                self._detect_diamond,
                self._detect_uups,
                self._detect_transparent,
                self._detect_beacon,
                self._detect_minimal_proxy,
                self._detect_custom_delegatecall,
            ]

            for strategy in strategies:
                result = strategy(contract)
                if result.proxy_type != ProxyType.NONE:
                    logger.debug(
                        "proxy_detected",
                        contract=contract.name,
                        proxy_type=result.proxy_type.value,
                        evidence=result.evidence,
                    )
                    return result

            return _DetectionResult(
                proxy_type=ProxyType.NONE,
                is_upgradeable=False,
                upgrade_function=None,
                admin_function=None,
                implementation_slot=None,
            )

        except Exception as exc:
            raise ProxyDetectionError(
                f"Proxy detection failed for {contract.name}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Strategy 1: Slither's built-in proxy analysis (0.10.x)
    # ------------------------------------------------------------------

    def _detect_slither_builtin(self, contract: Any) -> _DetectionResult:
        """Use Slither's own proxy detection flags when available."""
        is_proxy = getattr(contract, "is_upgradeable_proxy", False)
        is_upgradeable = getattr(contract, "is_upgradeable", False)

        if not (is_proxy or is_upgradeable):
            return _DetectionResult(ProxyType.NONE, False, None, None, None)

        # Try to find the proxy kind from Slither's detector results
        proxy_kind = getattr(contract, "upgradeable_version", None)
        upgrade_fn = self._find_upgrade_function(contract)
        admin_fn = self._find_admin_function(contract)

        if proxy_kind and "uups" in str(proxy_kind).lower():
            ptype = ProxyType.UUPS
        elif proxy_kind and "beacon" in str(proxy_kind).lower():
            ptype = ProxyType.BEACON
        elif proxy_kind and "transparent" in str(proxy_kind).lower():
            ptype = ProxyType.TRANSPARENT
        else:
            ptype = ProxyType.CUSTOM

        return _DetectionResult(
            proxy_type=ptype,
            is_upgradeable=is_upgradeable or is_proxy,
            upgrade_function=upgrade_fn,
            admin_function=admin_fn,
            implementation_slot=_IMPLEMENTATION_SLOT,
            evidence=["slither_builtin"],
        )

    # ------------------------------------------------------------------
    # Strategy 2: EIP-2535 Diamond
    # ------------------------------------------------------------------

    def _detect_diamond(self, contract: Any) -> _DetectionResult:
        func_names = {f.name for f in contract.functions}
        hits = func_names & _DIAMOND_FUNCTIONS

        if len(hits) >= 2:
            return _DetectionResult(
                proxy_type=ProxyType.DIAMOND,
                is_upgradeable=True,
                upgrade_function="diamondCut",
                admin_function=self._find_admin_function(contract),
                implementation_slot=None,
                evidence=[f"found diamond function: {h}" for h in hits],
            )
        return _DetectionResult(ProxyType.NONE, False, None, None, None)

    # ------------------------------------------------------------------
    # Strategy 3: UUPS
    # ------------------------------------------------------------------

    def _detect_uups(self, contract: Any) -> _DetectionResult:
        inheritance_names = {c.name for c in contract.inheritance}
        uups_hit = bool(inheritance_names & _UUPS_BASES)

        has_authorize = any(
            f.name == "_authorizeUpgrade" for f in contract.functions_inherited
        )
        has_upgrade = any(
            f.name in ("upgradeTo", "upgradeToAndCall") for f in contract.functions_inherited
        )

        if uups_hit or (has_authorize and has_upgrade):
            return _DetectionResult(
                proxy_type=ProxyType.UUPS,
                is_upgradeable=True,
                upgrade_function=self._find_upgrade_function(contract),
                admin_function=self._find_admin_function(contract),
                implementation_slot=_IMPLEMENTATION_SLOT,
                evidence=list(
                    filter(
                        None,
                        [
                            f"inherits {inheritance_names & _UUPS_BASES}" if uups_hit else None,
                            "_authorizeUpgrade present" if has_authorize else None,
                        ],
                    )
                ),
            )
        return _DetectionResult(ProxyType.NONE, False, None, None, None)

    # ------------------------------------------------------------------
    # Strategy 4: Transparent Proxy
    # ------------------------------------------------------------------

    def _detect_transparent(self, contract: Any) -> _DetectionResult:
        inheritance_names = {c.name for c in contract.inheritance}
        base_hit = inheritance_names & _TRANSPARENT_BASES

        func_names = {f.name for f in contract.functions}
        has_upgrade = bool(func_names & _UPGRADE_FUNCTIONS)
        has_impl_slot = self._has_eip1967_write(contract, _IMPLEMENTATION_SLOT)

        if base_hit or (has_upgrade and has_impl_slot):
            return _DetectionResult(
                proxy_type=ProxyType.TRANSPARENT,
                is_upgradeable=True,
                upgrade_function=self._find_upgrade_function(contract),
                admin_function=self._find_admin_function(contract),
                implementation_slot=_IMPLEMENTATION_SLOT,
                evidence=list(
                    filter(
                        None,
                        [
                            f"inherits {base_hit}" if base_hit else None,
                            "eip1967 implementation slot write" if has_impl_slot else None,
                        ],
                    )
                ),
            )
        return _DetectionResult(ProxyType.NONE, False, None, None, None)

    # ------------------------------------------------------------------
    # Strategy 5: Beacon Proxy
    # ------------------------------------------------------------------

    def _detect_beacon(self, contract: Any) -> _DetectionResult:
        inheritance_names = {c.name for c in contract.inheritance}
        beacon_hit = inheritance_names & _BEACON_BASES

        has_beacon_slot = self._has_eip1967_write(contract, _BEACON_SLOT)

        if beacon_hit or has_beacon_slot:
            return _DetectionResult(
                proxy_type=ProxyType.BEACON,
                is_upgradeable=True,
                upgrade_function="upgradeBeaconTo",
                admin_function=self._find_admin_function(contract),
                implementation_slot=_BEACON_SLOT,
                evidence=list(
                    filter(
                        None,
                        [
                            f"inherits {beacon_hit}" if beacon_hit else None,
                            "eip1967 beacon slot write" if has_beacon_slot else None,
                        ],
                    )
                ),
            )
        return _DetectionResult(ProxyType.NONE, False, None, None, None)

    # ------------------------------------------------------------------
    # Strategy 6: EIP-1167 Minimal Proxy Clone
    # ------------------------------------------------------------------

    def _detect_minimal_proxy(self, contract: Any) -> _DetectionResult:
        # EIP-1167 clones are identified by their runtime bytecode prefix.
        # Slither may not have runtime bytecode in static mode; fall back to
        # checking for the contract name pattern "Clone" or the absence of
        # functions combined with a known creation code pattern.
        name_lower = contract.name.lower()
        if "clone" in name_lower or "minimal" in name_lower:
            # Heuristic: minimal proxy clones are typically empty of state
            if not contract.state_variables and len(contract.functions) <= 2:
                return _DetectionResult(
                    proxy_type=ProxyType.MINIMAL,
                    is_upgradeable=False,
                    upgrade_function=None,
                    admin_function=None,
                    implementation_slot=None,
                    evidence=["name heuristic: clone/minimal + no state vars"],
                )
        return _DetectionResult(ProxyType.NONE, False, None, None, None)

    # ------------------------------------------------------------------
    # Strategy 7: Custom delegatecall-in-fallback proxy
    # ------------------------------------------------------------------

    def _detect_custom_delegatecall(self, contract: Any) -> _DetectionResult:
        """Catch-all: delegatecall present in fallback/receive."""
        for func in contract.functions:
            if not (func.is_fallback or func.is_receive):
                continue
            if self._function_has_delegatecall(func):
                return _DetectionResult(
                    proxy_type=ProxyType.CUSTOM,
                    is_upgradeable=False,
                    upgrade_function=self._find_upgrade_function(contract),
                    admin_function=self._find_admin_function(contract),
                    implementation_slot=None,
                    evidence=["delegatecall in fallback/receive"],
                )
        return _DetectionResult(ProxyType.NONE, False, None, None, None)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _function_has_delegatecall(func: Any) -> bool:
        """Return True if any IR node in the function is a delegatecall."""
        try:
            from slither.slithir.operations import LowLevelCall

            for node in func.nodes:
                for ir in node.irs:
                    if isinstance(ir, LowLevelCall):
                        if "delegatecall" in str(ir).lower():
                            return True
            # Fallback: string scan of the function source
            if func.source_mapping:
                return "delegatecall" in str(func).lower()
        except Exception:
            pass
        return False

    @staticmethod
    def _has_eip1967_write(contract: Any, slot_hex: str) -> bool:
        """Return True if any function writes to the given EIP-1967 slot."""
        slot_lower = slot_hex.lower().lstrip("0x")
        try:
            for func in contract.functions:
                for node in func.nodes:
                    node_str = str(node).lower()
                    if slot_lower in node_str or "sstore" in node_str:
                        return True
        except Exception:
            pass
        return False

    @staticmethod
    def _find_upgrade_function(contract: Any) -> Optional[str]:
        for func in contract.functions_inherited:
            if func.name in _UPGRADE_FUNCTIONS:
                return func.name
        return None

    @staticmethod
    def _find_admin_function(contract: Any) -> Optional[str]:
        admin_names = {"owner", "admin", "getAdmin", "proxyAdmin", "governance"}
        for func in contract.functions_inherited:
            if func.name in admin_names:
                return func.name
        return None


def build_proxy_relationship(
    contract_id: str,
    result: _DetectionResult,
    impl_contract_id: Optional[str] = None,
) -> ProxyRelationship:
    """
    Convert a _DetectionResult into a ProxyRelationship model node.

    Args:
        contract_id: ID of the proxy contract.
        result: Detection result from ProxyDetector.detect().
        impl_contract_id: Resolved implementation contract ID (if in-scope).
    """
    return ProxyRelationship(
        proxy_contract_id=contract_id,
        implementation_contract_id=impl_contract_id,
        proxy_type=result.proxy_type,
        implementation_slot=result.implementation_slot,
        is_upgradeable=result.is_upgradeable,
        upgrade_function=result.upgrade_function,
        admin_function=result.admin_function,
    )
