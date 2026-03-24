"""
Neo4j graph database persistence.

Stores the protocol graph in Neo4j for efficient querying and analysis.
"""

from typing import Optional

from neo4j import Driver, GraphDatabase, Session

from zeropath.exceptions import GraphDatabaseError
from zeropath.logging_config import get_logger
from zeropath.models import ProtocolGraph

logger = get_logger(__name__)


class Neo4jGraphDB:
    """
    Manages Neo4j graph database connections and operations.
    
    Stores:
    - Contracts as nodes
    - Functions as nodes
    - State variables as nodes
    - Relationships (calls, reads, writes, etc)
    """

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        database: str = "neo4j",
    ):
        """
        Initialize Neo4j connection.
        
        Args:
            uri: Neo4j connection URI (e.g., bolt://localhost:7687)
            username: Neo4j username
            password: Neo4j password
            database: Database name
        """
        self.uri = uri
        self.username = username
        self.password = password
        self.database = database
        self.driver: Optional[Driver] = None

    def connect(self) -> None:
        """Establish connection to Neo4j."""
        try:
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.username, self.password),
            )
            # Test connection
            self.driver.verify_connectivity()
            logger.info("neo4j_connected", uri=self.uri)
        except Exception as e:
            logger.error("neo4j_connection_failed", error=str(e))
            raise GraphDatabaseError(f"Failed to connect to Neo4j: {str(e)}") from e

    def disconnect(self) -> None:
        """Close connection to Neo4j."""
        if self.driver:
            self.driver.close()
            logger.info("neo4j_disconnected")

    def store_protocol_graph(self, graph: ProtocolGraph) -> None:
        """
        Store protocol graph in Neo4j.
        
        Creates nodes for:
        - Contracts
        - Functions
        - State Variables
        - External Dependencies
        
        Creates relationships for:
        - Function calls
        - State variable accesses (read/write)
        - Asset flows
        
        Args:
            graph: ProtocolGraph to store
            
        Raises:
            GraphDatabaseError: If storage fails
        """
        if not self.driver:
            raise GraphDatabaseError("Not connected to Neo4j")
        
        try:
            with self.driver.session(database=self.database) as session:
                # Clear existing data
                session.run("MATCH (n) DETACH DELETE n")
                logger.info("cleared_database")
                
                # Store contracts
                for contract in graph.contracts:
                    self._create_contract_node(session, contract)
                
                # Store functions
                for func in graph.functions:
                    self._create_function_node(session, func)
                
                # Store state variables
                for var in graph.state_variables:
                    self._create_state_variable_node(session, var)
                
                # Create relationships
                for call in graph.function_calls:
                    self._create_call_relationship(session, call)
                
                for flow in graph.asset_flows:
                    self._create_asset_flow_relationship(session, flow)
                
                logger.info(
                    "protocol_graph_stored",
                    contracts=len(graph.contracts),
                    functions=len(graph.functions),
                )
                
        except Exception as e:
            logger.error("graph_storage_failed", error=str(e))
            raise GraphDatabaseError(f"Failed to store graph in Neo4j: {str(e)}") from e

    def _create_contract_node(self, session: Session, contract) -> None:
        """Create a Contract node in Neo4j."""
        query = """
        CREATE (c:Contract {
            id: $id,
            name: $name,
            file_path: $file_path,
            is_library: $is_library,
            is_abstract: $is_abstract,
            language: $language
        })
        """
        session.run(
            query,
            id=contract.id,
            name=contract.name,
            file_path=contract.file_path,
            is_library=contract.is_library,
            is_abstract=contract.is_abstract,
            language=contract.language,
        )

    def _create_function_node(self, session: Session, func) -> None:
        """Create a Function node and relationship to Contract."""
        # Create function node
        func_query = """
        MATCH (c:Contract {id: $contract_id})
        CREATE (f:Function {
            id: $id,
            name: $name,
            visibility: $visibility,
            is_pure: $is_pure,
            is_view: $is_view,
            is_payable: $is_payable,
            line_start: $line_start,
            line_end: $line_end
        })-[:DEFINED_IN]->(c)
        RETURN f
        """
        session.run(
            func_query,
            id=func.id,
            name=func.name,
            contract_id=func.contract_id,
            visibility=func.visibility.value,
            is_pure=func.is_pure,
            is_view=func.is_view,
            is_payable=func.is_payable,
            line_start=func.line_start,
            line_end=func.line_end,
        )

    def _create_state_variable_node(self, session: Session, var) -> None:
        """Create a StateVariable node."""
        query = """
        CREATE (v:StateVariable {
            id: $id,
            name: $name,
            type: $type,
            visibility: $visibility,
            is_constant: $is_constant
        })
        """
        session.run(
            query,
            id=var.id,
            name=var.name,
            type=var.type_ or var.type,
            visibility=var.visibility.value,
            is_constant=var.is_constant,
        )

    def _create_call_relationship(self, session: Session, call) -> None:
        """Create a CALLS relationship between functions."""
        query = """
        MATCH (caller:Function {id: $caller_id})
        MATCH (callee:Function {id: $callee_id})
        CREATE (caller)-[:CALLS {
            line_number: $line_number,
            call_type: $call_type,
            is_delegatecall: $is_delegatecall
        }]->(callee)
        """
        if call.callee_id:
            session.run(
                query,
                caller_id=call.caller_id,
                callee_id=call.callee_id,
                line_number=call.line_number,
                call_type=call.call_type.value,
                is_delegatecall=call.is_delegatecall,
            )

    def _create_asset_flow_relationship(self, session: Session, flow) -> None:
        """Create an ASSET_FLOW relationship."""
        query = """
        MATCH (from:Function {id: $from_id})
        MATCH (to:Function {id: $to_id})
        CREATE (from)-[:ASSET_FLOW {
            asset_type: $asset_type,
            amount: $amount,
            is_conditional: $is_conditional
        }]->(to)
        """
        if flow.to_function_id:
            session.run(
                query,
                from_id=flow.from_function_id,
                to_id=flow.to_function_id,
                asset_type=flow.asset_type,
                amount=flow.amount,
                is_conditional=flow.is_conditional,
            )

    def query(self, cypher_query: str, **params) -> list[dict]:
        """
        Execute a Cypher query.
        
        Args:
            cypher_query: Cypher query string
            **params: Query parameters
            
        Returns:
            Query results
        """
        if not self.driver:
            raise GraphDatabaseError("Not connected to Neo4j")
        
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(cypher_query, params)
                return [dict(record) for record in result]
        except Exception as e:
            logger.error("query_failed", error=str(e))
            raise GraphDatabaseError(f"Query failed: {str(e)}") from e

    def get_contract_call_graph(self, contract_name: str) -> list[dict]:
        """Get the call graph for a specific contract."""
        query = """
        MATCH (c:Contract {name: $name})<-[:DEFINED_IN]-(f:Function)-[:CALLS]->(called:Function)
        RETURN f.name as caller, called.name as callee
        """
        return self.query(query, name=contract_name)

    def get_external_calls(self, function_name: str) -> list[dict]:
        """Get all external calls made by a function."""
        query = """
        MATCH (f:Function {name: $name})-[:CALLS {call_type: 'external'}]->(called:Function)
        RETURN called.name as external_call, called.is_payable as is_payable
        """
        return self.query(query, name=function_name)

    def get_asset_flow_paths(self, start_function: str) -> list[list[str]]:
        """Get asset flow paths from a starting function."""
        query = """
        MATCH path = (start:Function {name: $fn})-[:ASSET_FLOW*]->(end:Function)
        RETURN [n.name for n in nodes(path)] as path
        """
        results = self.query(query, fn=start_function)
        return [r["path"] for r in results]
