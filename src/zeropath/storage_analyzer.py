"""
EVM storage layout analyzer.

Implements the exact EVM storage packing rules defined in the Solidity
specification:

  https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html

Key rules:
  1. Variables are laid out in declaration order.
  2. Value types smaller than 32 bytes are packed right-to-left within a slot
     when consecutive variables fit together.
  3. A new slot is started if the next variable doesn't fit in the remaining
     bytes of the current slot.
  4. Structs and static arrays always start on a fresh slot boundary and
     consume whole slots.
  5. Dynamic types (mapping, dynamic array, bytes, string) always occupy
     exactly one slot (their data is stored elsewhere via keccak256).
  6. Constants and immutables do NOT occupy storage slots.

All sizes are in bytes. A slot is 32 bytes.
"""

import re
from dataclasses import dataclass
from typing import Any

from zeropath.exceptions import StorageExtractionError
from zeropath.logging_config import get_logger
from zeropath.models import StorageSlotInfo

logger = get_logger(__name__)

_SLOT_SIZE = 32  # bytes per EVM storage slot


# ---------------------------------------------------------------------------
# Internal data class
# ---------------------------------------------------------------------------


@dataclass
class _VarLayout:
    name: str
    slot: int
    byte_offset: int  # within slot, 0 = rightmost byte
    size_bytes: int
    is_packed: bool  # shares slot with another variable
    type_str: str


# ---------------------------------------------------------------------------
# Type size table
# ---------------------------------------------------------------------------


def _bytes_for_type(type_str: str) -> int:
    """
    Return the byte size of a Solidity type for storage layout purposes.

    Returns:
        - Exact byte count for packable value types (1-32).
        - 32 for reference types (mapping, dynamic array, bytes, string) —
          they each occupy one full slot as a pointer/length word.
        - 32 rounded-up to slot boundaries for static arrays and structs.

    The caller is responsible for handling slot-alignment requirements for
    structs and static arrays (they cannot be packed).
    """
    t = type_str.strip()

    # --- uint/int family ---
    if m := re.match(r"^u?int(\d+)$", t):
        return int(m.group(1)) // 8
    if t in ("uint", "int"):
        return 32  # default uint/int is 256-bit

    # --- address / address payable ---
    if t in ("address", "address payable"):
        return 20

    # --- bool ---
    if t == "bool":
        return 1

    # --- bytesN (fixed-size byte arrays, NOT dynamic bytes) ---
    if m := re.match(r"^bytes(\d+)$", t):
        return int(m.group(1))

    # --- Dynamic types: each gets its own slot (32 bytes as reference) ---
    if t in ("bytes", "string"):
        return 32
    if t.startswith("mapping("):
        return 32
    if t.endswith("[]"):  # dynamic array
        return 32

    # --- Static array: type[N] — must span whole slots, cannot be packed ---
    if m := re.match(r"^(.+)\[(\d+)\]$", t):
        element_type = m.group(1).strip()
        count = int(m.group(2))
        element_size = _bytes_for_type(element_type)
        # Each element is slot-aligned if it's >= 16 bytes or non-packable
        total_bytes = element_size * count
        # Round up to whole slots
        return ((total_bytes + _SLOT_SIZE - 1) // _SLOT_SIZE) * _SLOT_SIZE

    # --- Enum: stored as uint8 (minimum) up to the required bit width ---
    # Slither represents enums by name; default to 1 byte (uint8 equivalent)
    # unless we can introspect the member count.
    if t.startswith("enum "):
        return 1

    # --- Struct: slot-aligned (cannot be packed with other types) ---
    # Without member introspection we conservatively assign 1 full slot.
    # The graph_builder can pass a richer type string if Slither provides it.
    if t.startswith("struct "):
        return 32

    # --- Default: treat as full slot ---
    return 32


def _is_packable(type_str: str) -> bool:
    """
    Return True if a type can be packed with other variables within a slot.

    Only value types with size < 32 bytes are packable. Mappings, dynamic
    arrays, bytes, string, static arrays, and structs are NOT packable —
    they always start a fresh slot.
    """
    t = type_str.strip()

    # Dynamic reference types — not packable
    if t in ("bytes", "string"):
        return False
    if t.startswith("mapping("):
        return False
    if t.endswith("[]"):
        return False

    # Static arrays — not packable (slot-aligned requirement)
    if re.match(r"^.+\[\d+\]$", t):
        return False

    # Structs — not packable
    if t.startswith("struct "):
        return False

    size = _bytes_for_type(t)
    return size < _SLOT_SIZE


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------


class StorageAnalyzer:
    """
    Computes the EVM storage layout for a contract's state variables.

    Two public methods:
      - compute_layout(contract)  → list[_VarLayout]
      - analyze_packing(contract) → dict with slot statistics
    """

    def compute_layout(self, contract: Any) -> list[_VarLayout]:
        """
        Compute the storage slot assignment for every non-constant state variable.

        Constants and immutables are skipped — they do not occupy storage.

        Args:
            contract: A Slither Contract object.

        Returns:
            Ordered list of _VarLayout entries.

        Raises:
            StorageExtractionError
        """
        try:
            layouts: list[_VarLayout] = []
            current_slot = 0
            current_byte_offset = 0  # bytes consumed in current_slot so far

            for var in contract.state_variables:
                # Skip constants / immutables — they live in bytecode, not storage
                if var.is_constant or var.is_immutable:
                    continue

                type_str = str(var.type)
                size = _bytes_for_type(type_str)
                packable = _is_packable(type_str)

                if packable:
                    # Can we fit into the current slot?
                    if current_byte_offset + size > _SLOT_SIZE:
                        # Move to the next slot
                        current_slot += 1
                        current_byte_offset = 0

                    is_packed = current_byte_offset > 0  # sharing with prev var

                    layouts.append(
                        _VarLayout(
                            name=var.name,
                            slot=current_slot,
                            byte_offset=current_byte_offset,
                            size_bytes=size,
                            is_packed=is_packed,
                            type_str=type_str,
                        )
                    )
                    current_byte_offset += size

                    # If we've exactly filled a slot, advance
                    if current_byte_offset == _SLOT_SIZE:
                        current_slot += 1
                        current_byte_offset = 0
                else:
                    # Non-packable: must start on a fresh slot boundary
                    if current_byte_offset > 0:
                        current_slot += 1
                        current_byte_offset = 0

                    slot_count = max(1, size // _SLOT_SIZE)

                    layouts.append(
                        _VarLayout(
                            name=var.name,
                            slot=current_slot,
                            byte_offset=0,
                            size_bytes=size,
                            is_packed=False,
                            type_str=type_str,
                        )
                    )
                    current_slot += slot_count
                    # current_byte_offset stays 0

            logger.debug(
                "storage_layout_computed",
                contract=contract.name,
                variables=len(layouts),
                total_slots=current_slot,
            )
            return layouts

        except Exception as exc:
            logger.error("storage_extraction_failed", contract=contract.name, error=str(exc))
            raise StorageExtractionError(
                f"Storage layout failed for {contract.name}: {exc}"
            ) from exc

    def analyze_packing(self, contract: Any) -> dict:
        """
        Return a human-readable analysis of packing efficiency.

        Args:
            contract: A Slither Contract object.

        Returns:
            dict with keys:
              total_slots, packed_variables, wasted_bytes,
              packing_efficiency_pct, variable_details
        """
        layouts = self.compute_layout(contract)

        if not layouts:
            return {
                "total_slots": 0,
                "packed_variables": [],
                "wasted_bytes": 0,
                "packing_efficiency_pct": 100.0,
                "variable_details": [],
            }

        total_slots = layouts[-1].slot + max(
            1, layouts[-1].size_bytes // _SLOT_SIZE
        )
        used_bytes = sum(lay.size_bytes for lay in layouts)
        total_bytes = total_slots * _SLOT_SIZE
        wasted_bytes = total_bytes - used_bytes
        efficiency = (used_bytes / total_bytes * 100) if total_bytes else 100.0

        packed = [lay for lay in layouts if lay.is_packed]

        return {
            "total_slots": total_slots,
            "packed_variables": [p.name for p in packed],
            "wasted_bytes": wasted_bytes,
            "packing_efficiency_pct": round(efficiency, 2),
            "variable_details": [
                {
                    "name": lay.name,
                    "type": lay.type_str,
                    "slot": lay.slot,
                    "byte_offset": lay.byte_offset,
                    "size_bytes": lay.size_bytes,
                    "is_packed": lay.is_packed,
                }
                for lay in layouts
            ],
        }

    @staticmethod
    def to_storage_slot_info(layout: _VarLayout) -> StorageSlotInfo:
        """Convert a _VarLayout to the Pydantic StorageSlotInfo model."""
        return StorageSlotInfo(
            slot=layout.slot,
            byte_offset=layout.byte_offset,
            size_bytes=layout.size_bytes,
            is_packed=layout.is_packed,
        )
