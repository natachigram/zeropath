"""
Bytecode decompilation fallback for unverified contracts.

Primary backend: Heimdall-rs (https://github.com/Jon-Becker/heimdall-rs)
  - Produces pseudo-Solidity source + ABI JSON from raw EVM bytecode.
  - Called as subprocess: heimdall decompile <bytecode> --output <dir>

Fallback (no Heimdall installed): pure-Python EVM selector extraction.
  - Scans bytecode for the standard PUSH4 + EQ dispatcher pattern.
  - Builds stub Function models named func_<selector>.
  - State variables cannot be recovered without full decompilation.

Both paths always set is_degraded=True on the DecompileResult and the
caller is responsible for setting source_available=False on the graph.
"""

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from zeropath.exceptions import BytecodeDecompilationError
from zeropath.logging_config import get_logger
from zeropath.models import (
    AccessControl,
    Contract,
    ContractLanguage,
    Event,
    Function,
    FunctionSignature,
    Parameter,
    Visibility,
)

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class DecompileResult:
    """Output of a bytecode decompilation attempt."""

    contract_name: str
    contracts: list[Contract] = field(default_factory=list)
    functions: list[Function] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    abi: list[dict[str, Any]] = field(default_factory=list)
    source_code: str = ""
    is_degraded: bool = True
    decompiler: str = "unknown"


# ---------------------------------------------------------------------------
# Main decompiler class
# ---------------------------------------------------------------------------


class HeimdallDecompiler:
    """
    Wraps Heimdall-rs for EVM bytecode decompilation with a pure-Python fallback.

    Priority:
      1. Heimdall binary (full decompilation, ABI recovery, pseudo-Solidity output)
      2. Selector extraction from bytecode (no external dependency, partial recovery)

    Usage::

        decompiler = HeimdallDecompiler(heimdall_bin=Path("/usr/local/bin/heimdall"))
        result = decompiler.decompile("0x6080604052...", contract_name="Vault")
        # result.functions has stubs for every recovered function
    """

    def __init__(
        self,
        heimdall_bin: Optional[Path] = None,
        timeout: int = 60,
    ) -> None:
        """
        Args:
            heimdall_bin: Explicit path to the heimdall binary. If None, the
                          system PATH is searched automatically.
            timeout:      Subprocess timeout in seconds.
        """
        self._bin = heimdall_bin
        self._timeout = timeout
        self._available: Optional[bool] = None  # lazily evaluated

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_available(self) -> bool:
        """True if Heimdall is installed and responds to --version."""
        if self._available is None:
            self._available = self._check_heimdall()
        return self._available

    def decompile(
        self,
        bytecode_hex: str,
        contract_name: str = "Unknown",
        contract_id: Optional[str] = None,
    ) -> DecompileResult:
        """
        Decompile EVM bytecode into ZeroPath models.

        Args:
            bytecode_hex:  Raw bytecode as a hex string (with or without 0x).
            contract_name: Name to assign to the recovered contract.
            contract_id:   Pre-assigned UUID; auto-generated if None.

        Returns:
            DecompileResult with is_degraded=True and best-effort models.

        Raises:
            BytecodeDecompilationError: If bytecode is empty or irrecoverably invalid.
        """
        if not bytecode_hex or bytecode_hex in ("0x", "0x0"):
            raise BytecodeDecompilationError(
                f"Empty or EOA bytecode for '{contract_name}' — nothing to decompile."
            )

        # Normalise to 0x-prefixed
        if not bytecode_hex.startswith("0x"):
            bytecode_hex = "0x" + bytecode_hex

        if self.is_available:
            try:
                return self._decompile_with_heimdall(bytecode_hex, contract_name, contract_id)
            except BytecodeDecompilationError:
                raise
            except Exception as exc:
                logger.warning(
                    "heimdall_unexpected_error_falling_back",
                    contract=contract_name,
                    error=str(exc),
                )

        # Fallback: pure-Python selector extraction
        return self._decompile_fallback(bytecode_hex, contract_name, contract_id)

    # ------------------------------------------------------------------
    # Heimdall backend
    # ------------------------------------------------------------------

    def _check_heimdall(self) -> bool:
        """Return True if the heimdall binary exists and runs."""
        candidate = self._bin or shutil.which("heimdall")
        if not candidate:
            logger.debug("heimdall_not_found_on_path")
            return False
        try:
            result = subprocess.run(
                [str(candidate), "--version"],
                capture_output=True,
                timeout=10,
            )
            ok = result.returncode == 0
            if ok:
                version_line = result.stdout.decode(errors="replace").strip().split("\n")[0]
                logger.info("heimdall_detected", version=version_line)
            return ok
        except Exception:
            return False

    def _decompile_with_heimdall(
        self,
        bytecode_hex: str,
        contract_name: str,
        contract_id: Optional[str],
    ) -> DecompileResult:
        """Invoke Heimdall and parse its output directory."""
        heimdall_bin = self._bin or shutil.which("heimdall")

        with tempfile.TemporaryDirectory(prefix="zeropath_heimdall_") as tmpdir:
            output_dir = Path(tmpdir) / "out"
            output_dir.mkdir()

            cmd = [
                str(heimdall_bin),
                "decompile",
                bytecode_hex,
                "--output",
                str(output_dir),
                "--no-color",
            ]

            logger.info(
                "heimdall_decompile_start",
                contract=contract_name,
                bytecode_len=len(bytecode_hex),
            )
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                )
            except subprocess.TimeoutExpired:
                raise BytecodeDecompilationError(
                    f"Heimdall timed out after {self._timeout}s (contract: {contract_name})"
                )
            except FileNotFoundError:
                raise BytecodeDecompilationError(
                    "Heimdall binary not found — install from https://github.com/Jon-Becker/heimdall-rs"
                )

            if proc.returncode != 0:
                stderr_snippet = proc.stderr.strip()[:400]
                raise BytecodeDecompilationError(
                    f"Heimdall exited {proc.returncode}: {stderr_snippet}"
                )

            # Parse output artefacts
            decompiled_sol = ""
            abi_data: list[dict] = []

            sol_candidates = list(output_dir.rglob("*.sol"))
            abi_candidates = list(output_dir.rglob("abi.json")) + list(
                output_dir.rglob("*.abi.json")
            )

            if sol_candidates:
                decompiled_sol = sol_candidates[0].read_text(encoding="utf-8", errors="replace")
            if abi_candidates:
                try:
                    raw = abi_candidates[0].read_text(encoding="utf-8")
                    abi_data = json.loads(raw)
                except (json.JSONDecodeError, OSError) as exc:
                    logger.warning(
                        "heimdall_abi_parse_failed", contract=contract_name, error=str(exc)
                    )

            logger.info(
                "heimdall_decompile_complete",
                contract=contract_name,
                functions_in_abi=len([e for e in abi_data if e.get("type") == "function"]),
            )

            return self._build_result_from_abi(
                abi_data=abi_data,
                source_code=decompiled_sol,
                contract_name=contract_name,
                contract_id=contract_id,
                decompiler="heimdall",
            )

    # ------------------------------------------------------------------
    # Pure-Python fallback
    # ------------------------------------------------------------------

    def _decompile_fallback(
        self,
        bytecode_hex: str,
        contract_name: str,
        contract_id: Optional[str],
    ) -> DecompileResult:
        """
        Recover function selectors from EVM bytecode without Heimdall.

        Produces stub Function models named func_<selector> (e.g. func_a9059cbb).
        No state variables or events are recoverable by this method.
        """
        logger.info(
            "bytecode_fallback_mode",
            contract=contract_name,
            reason="heimdall_unavailable",
        )

        selectors = _extract_selectors_from_bytecode(bytecode_hex)
        logger.info(
            "selectors_extracted",
            count=len(selectors),
            contract=contract_name,
        )

        cid = contract_id or str(uuid4())
        contract = Contract(
            id=cid,
            name=contract_name,
            language=ContractLanguage.UNKNOWN,
            file_path="<bytecode>",
        )

        functions: list[Function] = []
        for selector in selectors:
            func_name = f"func_{selector[2:]}"  # strip 0x prefix
            functions.append(
                Function(
                    name=func_name,
                    contract_id=cid,
                    visibility=Visibility.EXTERNAL,
                    signature=FunctionSignature(name=func_name, selector=selector),
                    access_control=AccessControl(),
                )
            )

        return DecompileResult(
            contract_name=contract_name,
            contracts=[contract],
            functions=functions,
            decompiler="selector_extraction",
        )

    # ------------------------------------------------------------------
    # ABI → model conversion
    # ------------------------------------------------------------------

    def _build_result_from_abi(
        self,
        abi_data: list[dict],
        source_code: str,
        contract_name: str,
        contract_id: Optional[str],
        decompiler: str,
    ) -> DecompileResult:
        """Convert raw ABI + pseudo-Solidity source into ZeroPath models."""
        cid = contract_id or str(uuid4())
        contract = Contract(
            id=cid,
            name=contract_name,
            language=ContractLanguage.UNKNOWN,
            file_path="<bytecode>",
        )

        functions: list[Function] = []
        events: list[Event] = []

        for entry in abi_data:
            entry_type = entry.get("type", "function")
            if entry_type == "function":
                func = _abi_entry_to_function(entry, cid)
                if func:
                    functions.append(func)
            elif entry_type == "event":
                ev = _abi_entry_to_event(entry, cid)
                if ev:
                    events.append(ev)

        # When ABI is empty but we have pseudo-Solidity, mine function signatures
        if not functions and source_code:
            functions = _parse_functions_from_pseudo_sol(source_code, cid)

        return DecompileResult(
            contract_name=contract_name,
            contracts=[contract],
            functions=functions,
            events=events,
            abi=abi_data,
            source_code=source_code,
            is_degraded=True,
            decompiler=decompiler,
        )


# ---------------------------------------------------------------------------
# EVM dispatcher pattern — selector extraction
# ---------------------------------------------------------------------------


def _extract_selectors_from_bytecode(bytecode_hex: str) -> list[str]:
    """
    Scan EVM bytecode for the standard function dispatcher pattern.

    Recognises the sequence::

        PUSH4 <4-byte-selector>   (opcode 0x63)
        ...
        EQ                        (opcode 0x14, within 4 bytes)

    Returns a deduplicated ordered list of selector hex strings.
    Filters out common false-positives (all-zero selectors).
    """
    raw = bytecode_hex.lstrip("0x")
    try:
        data = bytes.fromhex(raw)
    except ValueError:
        logger.warning("invalid_bytecode_hex_for_selector_extraction", len=len(raw))
        return []

    selectors: list[str] = []
    seen: set[str] = set()
    i = 0

    while i < len(data) - 5:
        # PUSH4 opcode = 0x63; pushes the next 4 bytes onto the stack
        if data[i] == 0x63:
            selector_bytes = data[i + 1 : i + 5]
            selector_hex = selector_bytes.hex()

            # Skip zero-padded non-selectors
            if selector_hex != "00000000" and selector_hex not in seen:
                # Expect EQ (0x14) within the next 4 bytes (dispatcher pattern)
                window = data[i + 5 : i + 9]
                if 0x14 in window:
                    seen.add(selector_hex)
                    selectors.append("0x" + selector_hex)
            i += 5
        else:
            i += 1

    return selectors


# ---------------------------------------------------------------------------
# ABI entry → model helpers
# ---------------------------------------------------------------------------


def _abi_entry_to_function(entry: dict[str, Any], contract_id: str) -> Optional[Function]:
    """Convert one ABI function entry into a Function model."""
    try:
        name = entry.get("name") or "unknown"
        mutability = entry.get("stateMutability", "nonpayable")

        params = [
            Parameter(**{"name": inp.get("name") or f"p{i}", "type": inp.get("type", "bytes")})
            for i, inp in enumerate(entry.get("inputs", []))
        ]
        returns = [
            Parameter(**{"name": out.get("name") or f"r{i}", "type": out.get("type", "bytes")})
            for i, out in enumerate(entry.get("outputs", []))
        ]

        visibility = Visibility.EXTERNAL

        return Function(
            name=name,
            contract_id=contract_id,
            visibility=visibility,
            signature=FunctionSignature(name=name, parameters=params, returns=returns),
            is_pure=mutability == "pure",
            is_view=mutability == "view",
            is_payable=mutability == "payable",
            access_control=AccessControl(),
        )
    except Exception as exc:
        logger.warning(
            "abi_function_entry_skipped",
            error=str(exc),
            entry_snippet=str(entry)[:120],
        )
        return None


def _abi_entry_to_event(entry: dict[str, Any], contract_id: str) -> Optional[Event]:
    """Convert one ABI event entry into an Event model."""
    try:
        name = entry.get("name") or "UnknownEvent"
        params = [
            Parameter(
                **{
                    "name": inp.get("name") or f"p{i}",
                    "type": inp.get("type", "bytes"),
                    "indexed": inp.get("indexed", False),
                }
            )
            for i, inp in enumerate(entry.get("inputs", []))
        ]
        return Event(name=name, contract_id=contract_id, parameters=params)
    except Exception as exc:
        logger.warning("abi_event_entry_skipped", error=str(exc))
        return None


def _parse_functions_from_pseudo_sol(source_code: str, contract_id: str) -> list[Function]:
    """
    Mine function declarations from Heimdall pseudo-Solidity output.
    Used when the ABI file is missing or empty.
    """
    functions: list[Function] = []

    for match in re.finditer(r"\bfunction\s+(\w+)\s*\(([^)]*)\)", source_code):
        func_name = match.group(1)
        param_str = match.group(2).strip()

        params: list[Parameter] = []
        if param_str:
            for i, part in enumerate(param_str.split(",")):
                tokens = part.strip().split()
                if not tokens:
                    continue
                ptype = tokens[0]
                # Last token is the parameter name if there are >1 tokens
                pname = tokens[-1] if len(tokens) > 1 else f"p{i}"
                try:
                    params.append(Parameter(**{"name": pname, "type": ptype}))
                except Exception:
                    pass

        functions.append(
            Function(
                name=func_name,
                contract_id=contract_id,
                visibility=Visibility.EXTERNAL,
                signature=FunctionSignature(name=func_name, parameters=params),
                access_control=AccessControl(),
            )
        )

    return functions
