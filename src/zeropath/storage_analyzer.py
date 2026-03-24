"""
Storage layout extraction from contracts.

Analyzes state variables to build the storage layout,
including slot assignments and memory layout.
"""

from slither import Slither

from zeropath.exceptions import StorageExtractionError
from zeropath.logging_config import get_logger
from zeropath.models import StateVariable

logger = get_logger(__name__)


class StorageAnalyzer:
    """
    Analyzes and extracts storage layout from contracts.
    
    Determines:
    - Storage slots for each variable
    - Packing information
    - Memory layout for structs
    """

    @staticmethod
    def extract_storage_layout(contract) -> dict[str, int]:
        """
        Extract storage slot assignments for a contract.
        
        Returns:
            Dictionary mapping variable names to storage slots
        """
        try:
            storage_layout: dict[str, int] = {}
            slot = 0
            
            # Process state variables in order
            for var in contract.state_variables:
                var_size = StorageAnalyzer._estimate_variable_size(var)
                
                # Check if variable fits in current slot
                if slot * 32 % 32 + var_size > 32:
                    # Move to next slot
                    slot += (slot * 32 % 32 + var_size) // 32
                
                storage_layout[var.name] = slot
                
                # Update slot counter
                slot += var_size
            
            logger.debug("storage_layout_extracted", num_vars=len(storage_layout))
            return storage_layout
            
        except Exception as e:
            logger.error("storage_extraction_failed", error=str(e))
            raise StorageExtractionError(f"Failed to extract storage layout: {str(e)}") from e

    @staticmethod
    def _estimate_variable_size(var) -> int:
        """Estimate size of a variable in storage slots."""
        type_str = str(var.type)
        
        # Mappings and arrays use a single slot for the base
        if "mapping" in type_str or "[]" in type_str:
            return 1
        
        # Addresses, uint160, bytes20 = 20 bytes
        if "address" in type_str:
            return 1
        
        # uint/int types
        if "uint" in type_str or "int" in type_str:
            # Extract size (e.g., uint256, uint128)
            import re
            match = re.search(r"uint(\d+)|int(\d+)", type_str)
            if match:
                bit_size = int(match.group(1) or match.group(2))
                return (bit_size + 255) // 256  # Round up to full slots
            return 1  # Default uint256 = 1 slot
        
        # bytes types
        if "bytes" in type_str:
            import re
            match = re.search(r"bytes(\d+)", type_str)
            if match:
                byte_size = int(match.group(1))
                return (byte_size + 31) // 32
            return 1  # bytes (dynamic) uses 1 slot
        
        # bool = 1 byte (can be packed)
        if "bool" in type_str:
            return 1
        
        # Default to 1 slot
        return 1

    @staticmethod
    def analyze_packing(contract) -> dict:
        """
        Analyze variable packing efficiency.
        
        Returns:
            Analysis of how well variables are packed in storage
        """
        packing_info = {
            "total_slots": 0,
            "packed_variables": [],
            "wasted_bytes": 0,
        }
        
        slot = 0
        current_slot_used = 0
        
        for var in contract.state_variables:
            var_size = StorageAnalyzer._estimate_variable_size(var)
            
            if current_slot_used + var_size <= 32:
                packing_info["packed_variables"].append({
                    "name": var.name,
                    "slot": slot,
                    "offset": current_slot_used,
                })
                current_slot_used += var_size
            else:
                slot += 1
                current_slot_used = var_size
                packing_info["packed_variables"].append({
                    "name": var.name,
                    "slot": slot,
                    "offset": 0,
                })
        
        packing_info["total_slots"] = slot + 1
        packing_info["wasted_bytes"] = (slot + 1) * 32 - sum(
            StorageAnalyzer._estimate_variable_size(v) for v in contract.state_variables
        )
        
        return packing_info
