"""
Zeropath - Production-grade Solidity smart contract analyzer.

Builds structured protocol graphs for smart contract security research.
"""

__version__ = "0.1.0"

from zeropath.exceptions import ZeropathError
from zeropath.graph_builder import ProtocolGraphBuilder
from zeropath.graph_db import Neo4jGraphDB
from zeropath.models import ProtocolGraph
from zeropath.parser import ContractParser

__all__ = [
    "ZeropathError",
    "ContractParser",
    "ProtocolGraphBuilder",
    "ProtocolGraph",
    "Neo4jGraphDB",
]
