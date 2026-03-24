"""
Protocol graph construction orchestration.

Combines parsing, extraction, and analysis to build the complete protocol graph.
"""

from pathlib import Path
from typing import Optional

from zeropath.asset_flow import AssetFlowTracker
from zeropath.exceptions import GraphConstructionError
from zeropath.logging_config import get_logger
from zeropath.models import ProtocolGraph
from zeropath.parser import ContractParser
from zeropath.storage_analyzer import StorageAnalyzer

logger = get_logger(__name__)


class ProtocolGraphBuilder:
    """
    Orchestrates the construction of a complete protocol graph.
    
    This is the main entry point for analyzing a set of contracts.
    """

    def __init__(
        self,
        solc_version: Optional[str] = None,
        extract_storage: bool = True,
        extract_flows: bool = True,
    ):
        """
        Initialize the graph builder.
        
        Args:
            solc_version: Optional specific Solidity compiler version
            extract_storage: Whether to extract storage layouts
            extract_flows: Whether to extract asset flows
        """
        self.parser = ContractParser(solc_version)
        self.extract_storage = extract_storage
        self.extract_flows = extract_flows

    def build_from_files(self, contract_paths: list[Path]) -> ProtocolGraph:
        """
        Build protocol graph from a list of contract files.
        
        Args:
            contract_paths: List of paths to .sol files
            
        Returns:
            Complete protocol graph
            
        Raises:
            GraphConstructionError: If graph construction fails
        """
        try:
            graph = ProtocolGraph()
            
            logger.info("building_protocol_graph", num_files=len(contract_paths))
            
            for contract_path in contract_paths:
                contracts, functions, state_vars, calls = self.parser.parse_contract(contract_path)
                
                graph.contracts.extend(contracts)
                graph.functions.extend(functions)
                graph.state_variables.extend(state_vars)
                graph.function_calls.extend(calls)
            
            # Extract asset flows
            if self.extract_flows:
                logger.info("extracting_asset_flows")
                flows = AssetFlowTracker.extract_asset_flows(
                    graph.functions,
                    graph.function_calls,
                )
                graph.asset_flows.extend(flows)
            
            # Extract storage layouts
            if self.extract_storage:
                logger.info("extracting_storage_layouts")
                # Storage extraction would happen per-contract here
            
            graph.analysis_metadata = {
                "num_contracts": len(graph.contracts),
                "num_functions": len(graph.functions),
                "num_state_vars": len(graph.state_variables),
                "call_graph_edges": len(graph.function_calls),
                "asset_flows": len(graph.asset_flows),
            }
            
            logger.info(
                "protocol_graph_built",
                contracts=len(graph.contracts),
                functions=len(graph.functions),
                state_vars=len(graph.state_variables),
                calls=len(graph.function_calls),
            )
            
            return graph
            
        except Exception as e:
            logger.error("graph_construction_failed", error=str(e))
            raise GraphConstructionError(
                f"Failed to construct protocol graph: {str(e)}"
            ) from e

    def build_from_directory(
        self,
        directory: Path,
        recursive: bool = True,
    ) -> ProtocolGraph:
        """
        Build protocol graph from all contracts in a directory.
        
        Args:
            directory: Directory containing .sol files
            recursive: Whether to search subdirectories
            
        Returns:
            Complete protocol graph
        """
        pattern = "**/*.sol" if recursive else "*.sol"
        contract_files = list(directory.glob(pattern))
        
        if not contract_files:
            raise GraphConstructionError(f"No .sol files found in {directory}")
        
        logger.info("scanning_contracts", directory=str(directory), count=len(contract_files))
        return self.build_from_files(contract_files)
