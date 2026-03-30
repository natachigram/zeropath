"""
Slither-based contract parser — the core ingestion engine for Phase 1.

Fixes from the original implementation:
  - StateVariable now correctly references zeropath.models.StateVariable,
    not Slither's internal class (original critical bug).
  - source_mapping is accessed via .lines[], not .get() (which does not exist).
  - func.selector is bytes in Slither; converted to hex string.
  - StateVariable model now receives contract_id and line_start.
  - external_dependencies are extracted and returned.
  - Events are extracted.
  - Inheritance chain is fully flattened.
  - function_id_map is returned for downstream IR analysis (asset flows).

New in this version:
  - Vyper support: detect language from file extension and pragma.
  - Proxy detection integrated.
  - Storage layout populated per contract.
  - Compiler version extracted from pragma.
  - Access control: onlyRole detection extended beyond onlyOwner.
"""

import hashlib
import re
from pathlib import Path
from typing import Any, Optional

from zeropath.exceptions import ASTExtractionError, ParsingError
from zeropath.logging_config import get_logger
from zeropath.models import (
    AccessControl,
    CallType,
    ContractLanguage,
    Contract,
    Event,
    ExternalDependency,
    Function,
    FunctionCall,
    FunctionSignature,
    Parameter,
    StateVariable,
    StateVariableType,
    Visibility,
)
from zeropath.proxy_detector import ProxyDetector, build_proxy_relationship
from zeropath.storage_analyzer import StorageAnalyzer

logger = get_logger(__name__)

_proxy_detector = ProxyDetector()
_storage_analyzer = StorageAnalyzer()


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------


def detect_language(contract_path: Path) -> ContractLanguage:
    """Detect source language from file extension and pragma."""
    if contract_path.suffix == ".vy":
        return ContractLanguage.VYPER
    if contract_path.suffix == ".sol":
        return ContractLanguage.SOLIDITY
    # Inspect pragma line
    try:
        first_lines = contract_path.read_text(errors="replace")[:512]
        if "pragma solidity" in first_lines:
            return ContractLanguage.SOLIDITY
        if "@version" in first_lines or "# @version" in first_lines:
            return ContractLanguage.VYPER
    except OSError:
        pass
    return ContractLanguage.UNKNOWN


def extract_compiler_version(contract_path: Path) -> Optional[str]:
    """Extract the pragma version string from source."""
    try:
        source = contract_path.read_text(errors="replace")
        # Solidity: pragma solidity ^0.8.19;
        m = re.search(r"pragma\s+solidity\s+([^;]+);", source)
        if m:
            return m.group(1).strip()
        # Vyper: # @version 0.3.10
        m = re.search(r"#\s*@version\s+([\d.]+)", source)
        if m:
            return m.group(1).strip()
    except OSError:
        pass
    return None


def _source_hash(contract_path: Path) -> Optional[str]:
    try:
        data = contract_path.read_bytes()
        return hashlib.sha256(data).hexdigest()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Parser result dataclass
# ---------------------------------------------------------------------------


class ParseResult:
    """All data extracted from a single contract file."""

    __slots__ = (
        "contracts",
        "functions",
        "state_variables",
        "function_calls",
        "events",
        "external_dependencies",
        "proxy_relationships",
        "function_id_map",
        "slither_contracts",
        "source_available",
    )

    def __init__(self) -> None:
        self.contracts: list[Contract] = []
        self.functions: list[Function] = []
        self.state_variables: list[StateVariable] = []
        self.function_calls: list[FunctionCall] = []
        self.events: list[Event] = []
        self.external_dependencies: list[ExternalDependency] = []
        self.proxy_relationships: list = []
        # Maps "ContractName.functionName" → function UUID (for IR flows)
        self.function_id_map: dict[str, str] = {}
        # Raw Slither contract objects (needed for IR flow analysis)
        self.slither_contracts: list[Any] = []
        # False when contract was parsed from bytecode (no source available)
        self.source_available: bool = True


# ---------------------------------------------------------------------------
# ContractParser
# ---------------------------------------------------------------------------


class ContractParser:
    """
    Parse a single .sol or .vy file using Slither and return a ParseResult.

    Args:
        solc_version: Pin a specific compiler version (e.g. "0.8.19").
                      If None, Slither's auto-detection is used.
        extract_storage: Whether to compute storage layouts.
        detect_proxies:  Whether to run proxy pattern detection.
    """

    def __init__(
        self,
        solc_version: Optional[str] = None,
        extract_storage: bool = True,
        detect_proxies: bool = True,
    ) -> None:
        self.solc_version = solc_version
        self.extract_storage = extract_storage
        self.detect_proxies = detect_proxies

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def parse_contract(self, contract_path: Path) -> ParseResult:
        """
        Parse a contract file and return all extracted data.

        Accepts:
          - .sol / .vy files  → Slither-based full analysis
          - .bin files        → bytecode decompilation fallback

        Args:
            contract_path: Absolute path to a contract source or bytecode file.

        Returns:
            ParseResult populated with all extracted entities.

        Raises:
            ParsingError: If the file cannot be parsed.
        """
        if not contract_path.exists():
            raise ParsingError(f"Contract file not found: {contract_path}")

        # Route .bin (raw bytecode) files through the decompilation path
        if contract_path.suffix == ".bin":
            return self._parse_bytecode_file(contract_path)

        language = detect_language(contract_path)
        logger.info(
            "parsing_contract",
            path=str(contract_path),
            language=language.value,
        )

        try:
            from slither import Slither  # local import avoids top-level failures

            kwargs: dict = {}
            if self.solc_version:
                kwargs["solc"] = self.solc_version

            slither = Slither(str(contract_path), **kwargs)
        except Exception as exc:
            logger.error("slither_init_failed", path=str(contract_path), error=str(exc))
            raise ParsingError(f"Slither failed on {contract_path.name}: {exc}") from exc

        result = ParseResult()
        result.slither_contracts = list(slither.contracts)

        compiler_version = extract_compiler_version(contract_path)
        src_hash = _source_hash(contract_path)

        # Build a map of (contract_name, function_name) → slither function object
        # so _extract_calls can look up callees across contracts in the same file.
        all_slither_funcs: dict[tuple[str, str], Any] = {}
        for sc in slither.contracts:
            for f in sc.functions:
                all_slither_funcs[(sc.name, f.name)] = f

        for sc in slither.contracts:
            self._parse_one_contract(
                sc,
                contract_path,
                language,
                compiler_version,
                src_hash,
                result,
                all_slither_funcs,
            )

        logger.info(
            "contract_parsed",
            file=contract_path.name,
            contracts=len(result.contracts),
            functions=len(result.functions),
            state_vars=len(result.state_variables),
            events=len(result.events),
            calls=len(result.function_calls),
            external_deps=len(result.external_dependencies),
        )
        return result

    # ------------------------------------------------------------------
    # Per-contract extraction
    # ------------------------------------------------------------------

    def _parse_one_contract(
        self,
        sc: Any,
        contract_path: Path,
        language: ContractLanguage,
        compiler_version: Optional[str],
        src_hash: Optional[str],
        result: ParseResult,
        all_slither_funcs: dict[tuple[str, str], Any],
    ) -> None:
        """Extract all entities from one Slither contract object."""

        # --- Contract node ---
        contract_model = self._build_contract(
            sc, contract_path, language, compiler_version, src_hash
        )
        result.contracts.append(contract_model)

        # --- Proxy detection ---
        if self.detect_proxies:
            try:
                detection = _proxy_detector.detect(sc)
                contract_model.proxy_type = detection.proxy_type
                if detection.proxy_type.value != "none":
                    proxy_rel = build_proxy_relationship(contract_model.id, detection)
                    result.proxy_relationships.append(proxy_rel)
            except Exception as exc:
                logger.warning(
                    "proxy_detection_skipped",
                    contract=sc.name,
                    error=str(exc),
                )

        # --- State variables ---
        storage_map: dict[str, Any] = {}
        if self.extract_storage:
            try:
                layouts = _storage_analyzer.compute_layout(sc)
                storage_map = {lay.name: lay for lay in layouts}
            except Exception as exc:
                logger.warning(
                    "storage_layout_skipped", contract=sc.name, error=str(exc)
                )

        for var in sc.state_variables:
            sv = self._build_state_variable(var, contract_model.id, storage_map)
            result.state_variables.append(sv)

        # --- Functions ---
        func_models: list[Function] = []
        for sf in sc.functions:
            fm = self._build_function(sf, contract_model.id)
            func_models.append(fm)
            result.functions.append(fm)
            result.function_id_map[f"{sc.name}.{sf.name}"] = fm.id

        # --- Function calls ---
        for sf in sc.functions:
            caller_id = result.function_id_map.get(f"{sc.name}.{sf.name}")
            if not caller_id:
                continue
            calls = self._extract_calls(sf, sc, caller_id, result.function_id_map)
            result.function_calls.extend(calls)

        # --- Events ---
        try:
            for ev in sc.events:
                event_model = self._build_event(ev, contract_model.id)
                result.events.append(event_model)
        except Exception as exc:
            logger.warning("events_skipped", contract=sc.name, error=str(exc))

        # --- External dependencies ---
        ext_deps = self._extract_external_deps(sc, result.function_id_map)
        result.external_dependencies.extend(ext_deps)

    # ------------------------------------------------------------------
    # Builder helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_contract(
        sc: Any,
        contract_path: Path,
        language: ContractLanguage,
        compiler_version: Optional[str],
        src_hash: Optional[str],
    ) -> Contract:
        """Build a Contract model from a Slither contract object."""
        parent_names = [p.name for p in sc.inheritance]
        full_chain = _flatten_inheritance(sc)

        return Contract(
            name=sc.name,
            language=language,
            compiler_version=compiler_version,
            file_path=str(contract_path),
            is_library=sc.is_library,
            is_abstract=sc.is_abstract,
            is_interface=getattr(sc, "is_interface", False),
            parent_contracts=parent_names,
            full_inheritance=full_chain,
            source_hash=src_hash,
        )

    @staticmethod
    def _build_state_variable(
        var: Any,
        contract_id: str,
        storage_map: dict[str, Any],
    ) -> StateVariable:
        """Build a StateVariable model from a Slither state variable."""
        type_str = str(var.type)

        # Visibility
        vis_str = getattr(var, "visibility", "internal")
        visibility = _parse_visibility(str(vis_str))

        # Source line
        line_start = 0
        if var.source_mapping:
            lines = getattr(var.source_mapping, "lines", None)
            if lines:
                line_start = lines[0]

        # Storage slot
        from zeropath.storage_analyzer import StorageAnalyzer
        storage_info = None
        if var.name in storage_map:
            layout = storage_map[var.name]
            storage_info = StorageAnalyzer.to_storage_slot_info(layout)

        return StateVariable(
            **{
                "type": type_str,
                "name": var.name,
                "contract_id": contract_id,
                "visibility": visibility,
                "is_constant": bool(var.is_constant or var.is_immutable),
                "type_category": _categorize_type(type_str),
                "storage": storage_info,
                "line_start": line_start,
            }
        )

    @staticmethod
    def _build_function(sf: Any, contract_id: str) -> Function:
        """Build a Function model from a Slither function object."""
        visibility = _parse_visibility(str(sf.visibility))

        # Parameters
        params = [
            Parameter(**{"name": p.name or f"p{i}", "type": str(p.type)})
            for i, p in enumerate(sf.parameters)
        ]
        returns = [
            Parameter(**{"name": r.name or f"r{i}", "type": str(r.type)})
            for i, r in enumerate(sf.return_values)
        ]

        # Selector — Slither returns bytes4; convert to "0x..." hex string
        selector: Optional[str] = None
        raw_selector = getattr(sf, "selector", None)
        if raw_selector:
            if isinstance(raw_selector, (bytes, bytearray)):
                selector = "0x" + raw_selector.hex()
            elif isinstance(raw_selector, str):
                selector = raw_selector if raw_selector.startswith("0x") else "0x" + raw_selector

        sig = FunctionSignature(name=sf.name, parameters=params, returns=returns, selector=selector)

        # Modifiers
        modifier_names = [m.name for m in sf.modifiers]

        # Access control
        only_owner = "onlyOwner" in modifier_names
        only_role: Optional[str] = None
        for mod in modifier_names:
            if mod.startswith("onlyRole") or mod.startswith("requires") or "auth" in mod.lower():
                only_role = mod
                break

        ac = AccessControl(
            modifiers=modifier_names,
            onlyOwner=only_owner,
            onlyRole=only_role,
            requires_auth=only_owner or only_role is not None or bool(modifier_names),
        )

        # Source lines
        line_start, line_end = 0, 0
        if sf.source_mapping:
            lines = getattr(sf.source_mapping, "lines", None)
            if lines:
                line_start = lines[0]
                line_end = lines[-1]

        # State variable accesses
        svars_read = [v.name for v in sf.state_variables_read]
        svars_written = [v.name for v in sf.state_variables_written]

        return Function(
            name=sf.name,
            contract_id=contract_id,
            visibility=visibility,
            signature=sig,
            is_pure=bool(sf.pure),
            is_view=bool(sf.view),
            is_payable=bool(sf.payable),
            is_constructor=bool(sf.is_constructor),
            is_fallback=bool(sf.is_fallback),
            is_receive=bool(sf.is_receive),
            state_vars_read=svars_read,
            state_vars_written=svars_written,
            access_control=ac,
            modifiers=modifier_names,
            line_start=line_start,
            line_end=line_end,
        )

    @staticmethod
    def _extract_calls(
        sf: Any,
        sc: Any,
        caller_id: str,
        function_id_map: dict[str, str],
    ) -> list[FunctionCall]:
        """Extract all call edges originating from one function."""
        calls: list[FunctionCall] = []

        # --- Internal calls ---
        for internal_call in sf.internal_calls:
            func_name = getattr(internal_call, "name", str(internal_call))
            callee_id = function_id_map.get(f"{sc.name}.{func_name}")
            calls.append(
                FunctionCall(
                    caller_id=caller_id,
                    callee_id=callee_id,
                    callee_name=func_name,
                    call_type=CallType.INTERNAL,
                    line_number=_first_line(sf),
                )
            )

        # --- External calls ---
        for ext_call in sf.external_calls_as_expressions:
            call_str = str(ext_call)
            func_name = _extract_external_func_name(ext_call)
            is_delegatecall = "delegatecall" in call_str.lower()
            is_staticcall = "staticcall" in call_str.lower()
            has_value = ".value(" in call_str or "{value:" in call_str

            if is_delegatecall:
                call_type = CallType.DELEGATECALL
            elif is_staticcall:
                call_type = CallType.STATICCALL
            else:
                call_type = CallType.EXTERNAL

            # Try to resolve callee contract
            callee_contract = _extract_callee_contract(ext_call)
            callee_id = None
            if callee_contract and func_name:
                callee_id = function_id_map.get(f"{callee_contract}.{func_name}")

            calls.append(
                FunctionCall(
                    caller_id=caller_id,
                    callee_id=callee_id,
                    callee_name=func_name or str(ext_call)[:60],
                    callee_contract=callee_contract,
                    call_type=call_type,
                    is_delegatecall=is_delegatecall,
                    value_transfer=has_value,
                    line_number=_first_line(sf),
                )
            )

        # --- Low-level calls (via IR) ---
        try:
            from slither.slithir.operations import LowLevelCall

            for node in sf.nodes:
                for ir in node.irs:
                    if isinstance(ir, LowLevelCall):
                        calls.append(
                            FunctionCall(
                                caller_id=caller_id,
                                callee_name=str(getattr(ir, "function_name", "call")),
                                call_type=CallType.LOW_LEVEL,
                                is_delegatecall="delegatecall" in str(ir).lower(),
                                value_transfer=getattr(ir, "call_value", None) not in (None, 0),
                                line_number=_first_line(sf),
                            )
                        )
        except Exception:
            pass  # IR not available in this Slither version

        return calls

    @staticmethod
    def _build_event(ev: Any, contract_id: str) -> Event:
        """Build an Event model from a Slither event object."""
        params = []
        for p in getattr(ev, "elems", []):
            param_name = getattr(p, "name", "") or "param"
            param_type = str(getattr(p, "type", "unknown"))
            indexed = getattr(p, "indexed", False)
            params.append(Parameter(**{"name": param_name, "type": param_type, "indexed": indexed}))

        line_start = 0
        if hasattr(ev, "source_mapping") and ev.source_mapping:
            lines = getattr(ev.source_mapping, "lines", None)
            if lines:
                line_start = lines[0]

        return Event(
            name=ev.name,
            contract_id=contract_id,
            parameters=params,
            line_start=line_start,
        )

    @staticmethod
    def _extract_external_deps(
        sc: Any,
        function_id_map: dict[str, str],
    ) -> list[ExternalDependency]:
        """
        Extract external contract dependencies by looking at high-level calls
        to contracts NOT defined in the same file.
        """
        deps: dict[str, ExternalDependency] = {}

        all_known_contracts = set(function_id_map.keys())
        # Get set of contract names defined in this parse run
        known_names: set[str] = {k.split(".")[0] for k in all_known_contracts}

        for func in sc.functions:
            caller_key = f"{sc.name}.{func.name}"
            caller_id = function_id_map.get(caller_key)

            for ext_call in func.external_calls_as_expressions:
                callee_contract = _extract_callee_contract(ext_call)
                func_name = _extract_external_func_name(ext_call)

                if callee_contract and callee_contract not in known_names:
                    if callee_contract not in deps:
                        deps[callee_contract] = ExternalDependency(
                            name=callee_contract,
                            interface=_guess_interface(callee_contract),
                        )
                    if caller_id and caller_id not in deps[callee_contract].references:
                        deps[callee_contract].references.append(caller_id)
                    if func.name not in deps[callee_contract].call_sites:
                        deps[callee_contract].call_sites.append(
                            f"{sc.name}.{func.name}"
                        )

        return list(deps.values())

    # ------------------------------------------------------------------
    # Bytecode path
    # ------------------------------------------------------------------

    def _parse_bytecode_file(self, contract_path: Path) -> ParseResult:
        """
        Parse a .bin file (raw EVM bytecode) via HeimdallDecompiler.

        The returned ParseResult has source_available=False and contains
        degraded models (stub functions named func_<selector>).
        """
        bytecode_hex = contract_path.read_text(encoding="utf-8").strip()
        contract_name = contract_path.stem

        logger.info(
            "parsing_bytecode_file",
            path=str(contract_path),
            contract=contract_name,
            bytecode_len=len(bytecode_hex),
        )

        return self.parse_bytecode(bytecode_hex, contract_name=contract_name)

    def parse_bytecode(
        self,
        bytecode_hex: str,
        contract_name: str = "Unknown",
    ) -> ParseResult:
        """
        Decompile raw EVM bytecode and return a degraded ParseResult.

        Uses Heimdall-rs when available; falls back to selector extraction.

        Args:
            bytecode_hex:  EVM bytecode as a hex string (0x-prefixed or bare).
            contract_name: Human-readable name to assign to the recovered contract.

        Returns:
            ParseResult with source_available=False and is_degraded stubs.
        """
        from zeropath.bytecode_decompiler import HeimdallDecompiler
        from zeropath.config import get_settings

        settings = get_settings()
        decompiler = HeimdallDecompiler(
            heimdall_bin=settings.heimdall_bin,
            timeout=settings.heimdall_timeout_seconds,
        )

        try:
            decompile_result = decompiler.decompile(
                bytecode_hex, contract_name=contract_name
            )
        except Exception as exc:
            logger.error(
                "bytecode_decompilation_failed",
                contract=contract_name,
                error=str(exc),
            )
            raise ParsingError(
                f"Bytecode decompilation failed for '{contract_name}': {exc}"
            ) from exc

        result = ParseResult()
        result.source_available = False
        result.contracts.extend(decompile_result.contracts)
        result.functions.extend(decompile_result.functions)
        result.events.extend(decompile_result.events)

        # Build function_id_map for downstream asset-flow analysis
        for contract in decompile_result.contracts:
            for func in decompile_result.functions:
                if func.contract_id == contract.id:
                    result.function_id_map[f"{contract.name}.{func.name}"] = func.id

        logger.info(
            "bytecode_parsed",
            contract=contract_name,
            functions=len(result.functions),
            events=len(result.events),
            decompiler=decompile_result.decompiler,
        )
        return result


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _flatten_inheritance(sc: Any) -> list[str]:
    """Return the full flattened inheritance chain (breadth-first)."""
    result: list[str] = []
    seen: set[str] = set()
    queue = list(sc.inheritance)
    while queue:
        parent = queue.pop(0)
        if parent.name not in seen:
            seen.add(parent.name)
            result.append(parent.name)
            queue.extend(parent.inheritance)
    return result


def _parse_visibility(vis_str: str) -> Visibility:
    """Map a Slither visibility string to our Visibility enum."""
    v = vis_str.lower()
    if "public" in v:
        return Visibility.PUBLIC
    if "external" in v:
        return Visibility.EXTERNAL
    if "private" in v:
        return Visibility.PRIVATE
    return Visibility.INTERNAL


def _categorize_type(type_str: str) -> StateVariableType:
    """Map a Solidity type string to our StateVariableType enum."""
    t = type_str.lower()
    if t.startswith("mapping"):
        return StateVariableType.MAPPING
    if "[]" in t or re.search(r"\[\d+\]", t):
        return StateVariableType.ARRAY
    if "address" in t:
        return StateVariableType.ADDRESS
    if t.startswith("bytes") and not t == "bytes":
        return StateVariableType.BYTES
    if t == "bytes":
        return StateVariableType.BYTES
    if t == "string":
        return StateVariableType.STRING
    if "struct" in t:
        return StateVariableType.STRUCT
    if "enum" in t:
        return StateVariableType.ENUM
    return StateVariableType.PRIMITIVE


def _first_line(func: Any) -> int:
    """Return the first source line of a Slither function, or 0."""
    if func.source_mapping:
        lines = getattr(func.source_mapping, "lines", None)
        if lines:
            return lines[0]
    return 0


def _extract_external_func_name(ext_call: Any) -> Optional[str]:
    """Best-effort extraction of the function name from an external call expression."""
    try:
        # Slither expression types vary; try common attributes
        if hasattr(ext_call, "called") and hasattr(ext_call.called, "member_name"):
            return ext_call.called.member_name
        if hasattr(ext_call, "member_name"):
            return ext_call.member_name
        # Fallback: parse "contract.funcName(" from string repr
        m = re.search(r"\.(\w+)\s*\(", str(ext_call))
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def _extract_callee_contract(ext_call: Any) -> Optional[str]:
    """Best-effort extraction of the callee contract name from an external call."""
    try:
        if hasattr(ext_call, "called"):
            expr = ext_call.called
            if hasattr(expr, "expression") and hasattr(expr.expression, "type"):
                return str(expr.expression.type).split("(")[0].strip()
            if hasattr(expr, "value") and hasattr(expr.value, "type"):
                return str(expr.value.type).split("(")[0].strip()
        m = re.match(r"(\w+)\.", str(ext_call))
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


_KNOWN_INTERFACES: dict[str, str] = {
    "IERC20": "ERC20",
    "ERC20": "ERC20",
    "IERC721": "ERC721",
    "ERC721": "ERC721",
    "IERC1155": "ERC1155",
    "IUniswapV2Pair": "UniswapV2",
    "IUniswapV2Router": "UniswapV2",
    "IUniswapV3Pool": "UniswapV3",
    "IChainlinkAggregator": "Chainlink",
    "AggregatorV3Interface": "Chainlink",
    "IWETH": "WETH",
    "IVault": "Vault",
    "IFlashLoan": "FlashLoan",
    "ILendingPool": "Aave",
    "ICErc20": "Compound",
}


def _guess_interface(contract_name: str) -> Optional[str]:
    """Return a known interface label for a contract name, if recognisable."""
    return _KNOWN_INTERFACES.get(contract_name)
