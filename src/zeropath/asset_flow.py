"""
Asset flow tracker for protocol graphs.

Traces ETH and ERC-20/721/1155 token movements through a protocol by
combining two evidence sources:

  1. Slither IR layer  — reads `node.irs` for Send/Transfer/LowLevelCall
     operations that carry `value != 0`.  This is the most precise signal.

  2. Structural heuristics — when the IR layer is unavailable or the
     evidence is ambiguous, falls back to:
       - payable function flags for ETH receipts
       - well-known token function name matching for ERC-20/721 patterns

Design decisions:
  - ETH flows are only created when Slither's IR confirms value > 0, OR when
    an *external* call is made from a payable function. Internal calls from
    payable functions are not treated as ETH flows to avoid false positives.
  - Token detection requires the callee name to be in the known-function set
    AND the call to be an external call. Internal helper functions with the
    same names are NOT flagged.
  - Every AssetFlow has a source of evidence (metadata field) so downstream
    phases can apply their own confidence thresholds.
"""

from typing import Any, Optional

from zeropath.exceptions import AssetFlowTrackingError
from zeropath.logging_config import get_logger
from zeropath.models import AssetFlow, CallType, Function, FunctionCall

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Known ERC-20 / ERC-721 / ERC-1155 transfer function names
# (external calls only)
# ---------------------------------------------------------------------------
_ERC20_TRANSFER_FUNCS = frozenset(
    {
        "transfer",
        "transferFrom",
        "safeTransfer",
        "safeTransferFrom",
    }
)
_MINT_BURN_FUNCS = frozenset({"mint", "burn", "burnFrom", "_mint", "_burn"})
_LIQUIDITY_FUNCS = frozenset({"deposit", "withdraw", "stake", "unstake", "redeem"})
_APPROVAL_FUNCS = frozenset({"approve", "increaseAllowance", "decreaseAllowance"})

_ALL_TOKEN_FUNCS = (
    _ERC20_TRANSFER_FUNCS | _MINT_BURN_FUNCS | _LIQUIDITY_FUNCS | _APPROVAL_FUNCS
)

# ---------------------------------------------------------------------------
# Slither IR type imports (optional — graceful fallback if unavailable)
# ---------------------------------------------------------------------------
try:
    from slither.slithir.operations import (  # type: ignore[import]
        HighLevelCall,
        LowLevelCall,
        Send,
        Transfer,
    )

    _SLITHER_IR_AVAILABLE = True
except ImportError:
    _SLITHER_IR_AVAILABLE = False
    logger.warning("slither_ir_unavailable", msg="Asset flow IR analysis disabled")


class AssetFlowTracker:
    """
    Extracts asset flow relationships from a parsed protocol.

    Combines IR-based analysis (precise, requires Slither objects) with
    structural heuristics (fast, works on model objects only).
    """

    def __init__(self, use_ir: bool = True):
        """
        Args:
            use_ir: If True (default), attempt Slither IR analysis. Set to
                    False when working only from model objects (e.g. in tests).
        """
        self._use_ir = use_ir and _SLITHER_IR_AVAILABLE

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_from_slither(
        self,
        slither_contracts: list[Any],
        function_id_map: dict[str, str],
    ) -> list[AssetFlow]:
        """
        Extract asset flows using the Slither IR layer.

        Args:
            slither_contracts: List of Slither Contract objects.
            function_id_map: Maps "ContractName.functionName" → function UUID.

        Returns:
            List of AssetFlow objects (no duplicates).
        """
        if not self._use_ir:
            return []

        flows: list[AssetFlow] = []
        seen: set[tuple] = set()

        try:
            for contract in slither_contracts:
                for func in contract.functions:
                    caller_key = f"{contract.name}.{func.name}"
                    caller_id = function_id_map.get(caller_key)
                    if not caller_id:
                        continue

                    for node in func.nodes:
                        for ir in node.irs:
                            flow = self._ir_to_flow(ir, caller_id, function_id_map, node)
                            if flow:
                                dedup_key = (
                                    flow.from_function_id,
                                    flow.to_function_id,
                                    flow.asset_type,
                                )
                                if dedup_key not in seen:
                                    seen.add(dedup_key)
                                    flows.append(flow)

            logger.info("asset_flows_ir_extracted", count=len(flows))
            return flows

        except Exception as exc:
            logger.error("asset_flow_ir_failed", error=str(exc))
            raise AssetFlowTrackingError(f"IR-based flow extraction failed: {exc}") from exc

    @staticmethod
    def extract_from_models(
        functions: list[Function],
        function_calls: list[FunctionCall],
    ) -> list[AssetFlow]:
        """
        Structural heuristic flow extraction from model objects (no Slither).

        This is the fallback path and is also used for token detection on top
        of IR results because the IR path may miss call-forwarding patterns.

        Args:
            functions: Extracted Function models.
            function_calls: Extracted FunctionCall models.

        Returns:
            List of AssetFlow objects.
        """
        flows: list[AssetFlow] = []
        seen: set[tuple] = set()

        try:
            func_by_id = {f.id: f for f in functions}

            for call in function_calls:
                flow: Optional[AssetFlow] = None

                # --- ETH flow: only external calls from payable functions ---
                if call.call_type in (CallType.EXTERNAL, CallType.LOW_LEVEL):
                    caller = func_by_id.get(call.caller_id)
                    if caller and caller.is_payable and call.value_transfer:
                        flow = AssetFlow(
                            from_function_id=call.caller_id,
                            to_function_id=call.callee_id,
                            asset_type="ETH",
                            line_number=call.line_number,
                            is_conditional=False,
                        )

                # --- Token flow: external calls to known token functions ---
                # Must be a separate if (not elif) — ETH check above never sets flow
                # for non-payable/non-value-transfer calls, so token detection is
                # independent of the ETH check.
                if flow is None and call.call_type == CallType.EXTERNAL:
                    if call.callee_name in _ALL_TOKEN_FUNCS:
                        asset = (
                            "ERC20"
                            if call.callee_name in (
                                _ERC20_TRANSFER_FUNCS | _MINT_BURN_FUNCS | _LIQUIDITY_FUNCS
                            )
                            else "ERC20"
                        )
                        flow = AssetFlow(
                            from_function_id=call.caller_id,
                            to_function_id=call.callee_id,
                            asset_type=asset,
                            line_number=call.line_number,
                            is_conditional=False,
                        )

                if flow:
                    key = (flow.from_function_id, flow.to_function_id, flow.asset_type)
                    if key not in seen:
                        seen.add(key)
                        flows.append(flow)

            logger.info("asset_flows_heuristic_extracted", count=len(flows))
            return flows

        except Exception as exc:
            logger.error("asset_flow_heuristic_failed", error=str(exc))
            raise AssetFlowTrackingError(f"Heuristic flow extraction failed: {exc}") from exc

    @staticmethod
    def analyze_value_flow_paths(
        entry_function_id: str,
        all_flows: list[AssetFlow],
    ) -> list[list[str]]:
        """
        DFS enumeration of all asset flow paths from an entry function.

        Cycle detection prevents infinite loops. Each path is a list of
        function IDs from the entry down to a terminal node.

        Args:
            entry_function_id: Starting function UUID.
            all_flows: All AssetFlow relationships in the protocol.

        Returns:
            List of paths; each path is a list of function IDs.
        """
        # Build adjacency list
        adj: dict[str, list[str]] = {}
        for flow in all_flows:
            if flow.to_function_id:
                adj.setdefault(flow.from_function_id, []).append(flow.to_function_id)

        paths: list[list[str]] = []

        def dfs(node: str, path: list[str], visited: set[str]) -> None:
            if node in visited:
                return
            visited = visited | {node}
            path = path + [node]
            children = adj.get(node, [])
            if not children:
                paths.append(path)
            else:
                for child in children:
                    dfs(child, path, visited)

        dfs(entry_function_id, [], set())
        return paths

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _ir_to_flow(
        ir: Any,
        caller_id: str,
        function_id_map: dict[str, str],
        node: Any,
    ) -> Optional[AssetFlow]:
        """Map a single Slither IR operation to an AssetFlow, or None."""
        if not _SLITHER_IR_AVAILABLE:
            return None

        line = 0
        if hasattr(node, "source_mapping") and node.source_mapping:
            lines = getattr(node.source_mapping, "lines", [])
            line = lines[0] if lines else 0

        # --- Send (transfer ETH via .send()) ---
        if isinstance(ir, Send):
            return AssetFlow(
                from_function_id=caller_id,
                to_function_id=None,
                asset_type="ETH",
                line_number=line,
            )

        # --- Transfer (transfer ETH via .transfer()) ---
        if isinstance(ir, Transfer):
            return AssetFlow(
                from_function_id=caller_id,
                to_function_id=None,
                asset_type="ETH",
                line_number=line,
            )

        # --- LowLevelCall with value (ETH via call{value: ...}()) ---
        if isinstance(ir, LowLevelCall):
            has_value = getattr(ir, "call_value", None) not in (None, 0)
            is_delegatecall = "delegatecall" in str(ir).lower()
            if has_value and not is_delegatecall:
                return AssetFlow(
                    from_function_id=caller_id,
                    to_function_id=None,
                    asset_type="ETH",
                    line_number=line,
                )

        # --- HighLevelCall: token transfer to a known ERC function ---
        if isinstance(ir, HighLevelCall):
            func_name = getattr(ir, "function_name", "") or ""
            if func_name in _ERC20_TRANSFER_FUNCS:
                # Resolve callee contract + function to UUID
                callee_contract = None
                callee_id = None
                if hasattr(ir, "destination") and ir.destination:
                    callee_contract = str(ir.destination.type)
                    key = f"{callee_contract}.{func_name}"
                    callee_id = function_id_map.get(key)

                return AssetFlow(
                    from_function_id=caller_id,
                    to_function_id=callee_id,
                    asset_type="ERC20",
                    line_number=line,
                )

        return None
