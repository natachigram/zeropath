"""EVM/Solidity adapter."""

from zeropath.adapters.evm.adapter import EVMAdapter
from zeropath.adapters.evm.detector import detect_evm_project

__all__ = ["EVMAdapter", "detect_evm_project"]
