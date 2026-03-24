"""
Asset flow tracking through the protocol graph.

Traces ETH and token transfers through functions to understand
the flow of value through the protocol.
"""

from typing import Optional

from zeropath.exceptions import AssetFlowTrackingError
from zeropath.logging_config import get_logger
from zeropath.models import AssetFlow, CallType, Function, FunctionCall

logger = get_logger(__name__)


class AssetFlowTracker:
    """
    Tracks asset (ETH, tokens) flows through the protocol.
    
    Identifies:
    - Functions that receive/send assets
    - Asset transfer paths
    - Conditional transfers
    """

    @staticmethod
    def extract_asset_flows(
        functions: list[Function],
        function_calls: list[FunctionCall],
    ) -> list[AssetFlow]:
        """
        Extract asset flow information from functions and calls.
        
        Args:
            functions: List of extracted functions
            function_calls: List of extracted function calls
            
        Returns:
            List of asset flow relationships
        """
        flows: list[AssetFlow] = []
        
        try:
            # Identify functions that handle value
            payable_functions = {f.id for f in functions if f.is_payable}
            
            # Identify functions that make external calls (potential value transfers)
            external_callers = {}
            for call in function_calls:
                if call.call_type == CallType.EXTERNAL or call.is_delegatecall:
                    if call.caller_id not in external_callers:
                        external_callers[call.caller_id] = []
                    external_callers[call.caller_id].append(call)
            
            # Track flows from payable functions through call chains
            for func in functions:
                if func.is_payable:
                    # This function receives ETH
                    flows.extend(
                        AssetFlowTracker._trace_eth_transfers(
                            func, functions, function_calls, payable_functions
                        )
                    )
            
            # Track token transfer patterns
            flows.extend(
                AssetFlowTracker._detect_token_transfers(functions, function_calls)
            )
            
            logger.info("asset_flows_extracted", count=len(flows))
            return flows
            
        except Exception as e:
            logger.error("asset_flow_tracking_failed", error=str(e))
            raise AssetFlowTrackingError(f"Failed to track asset flows: {str(e)}") from e

    @staticmethod
    def _trace_eth_transfers(
        func: Function,
        all_functions: list[Function],
        all_calls: list[FunctionCall],
        payable_funcs: set[str],
    ) -> list[AssetFlow]:
        """Trace ETH transfers starting from a payable function."""
        flows: list[AssetFlow] = []
        
        # Find calls made by this function
        outgoing_calls = [c for c in all_calls if c.caller_id == func.id]
        
        for call in outgoing_calls:
            if call.callee_id:
                callee = next(
                    (f for f in all_functions if f.id == call.callee_id), None
                )
                if callee:
                    flows.append(AssetFlow(
                        from_function_id=func.id,
                        to_function_id=callee.id,
                        asset_type="ETH",
                        line_number=call.line_number,
                    ))
        
        return flows

    @staticmethod
    def _detect_token_transfers(
        functions: list[Function],
        function_calls: list[FunctionCall],
    ) -> list[AssetFlow]:
        """Detect token transfer patterns."""
        flows: list[AssetFlow] = []
        
        # Common token transfer function names
        token_functions = {
            "transfer", "transferFrom", "mint", "burn",
            "approve", "safeTransfer", "deposit", "withdraw"
        }
        
        for call in function_calls:
            if call.callee_name in token_functions:
                flows.append(AssetFlow(
                    from_function_id=call.caller_id,
                    to_function_id=call.callee_id,
                    asset_type="ERC20",  # Could be more specific
                    line_number=call.line_number,
                ))
        
        return flows

    @staticmethod
    def analyze_value_flow_paths(
        entry_function_id: str,
        all_functions: list[Function],
        all_calls: list[FunctionCall],
    ) -> list[list[str]]:
        """
        Analyze all paths that value can take from an entry function.
        
        Args:
            entry_function_id: Starting function ID
            all_functions: All functions in protocol
            all_calls: All function calls in protocol
            
        Returns:
            List of paths (each path is a list of function IDs)
        """
        paths: list[list[str]] = []
        
        def dfs(func_id: str, path: list[str], visited: set[str]) -> None:
            """Depth-first search to find all paths."""
            if func_id in visited:  # Prevent infinite loops
                return
            
            visited.add(func_id)
            path.append(func_id)
            
            # Find all calls from this function
            outgoing = [c for c in all_calls if c.caller_id == func_id and c.callee_id]
            
            if not outgoing:
                # Leaf node, record path
                paths.append(path.copy())
            else:
                for call in outgoing:
                    dfs(call.callee_id, path.copy(), visited.copy())
        
        dfs(entry_function_id, [], set())
        return paths
