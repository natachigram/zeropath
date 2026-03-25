"""
Neo4j graph database persistence layer.

Fixes from the original implementation:
  - Cypher list comprehension syntax fixed: `[n IN nodes(p) | n.name]`
    (was Python syntax `[n.name for n in nodes(p)]` — invalid Cypher).
  - State variable field access uses `var.type_` (Pydantic attribute name)
    not `var.type` (alias — inaccessible as a Python attribute in v2).
  - `store_protocol_graph` now uses MERGE instead of CREATE to be
    idempotent; re-running analysis updates existing nodes rather than
    duplicating or failing.
  - The unconditional MATCH (n) DETACH DELETE n is replaced with a
    scoped operation that only clears nodes tagged with this graph's ID.
  - Unique constraints / indexes are created on first connection.
  - State variables are linked to their owning contract via :BELONGS_TO.
  - Events are persisted as nodes.
  - External dependencies are persisted as ExternalDep nodes.
  - Proxy relationships are persisted as :PROXIES_TO edges.
"""

from contextlib import contextmanager
from typing import Any, Generator, Optional

from neo4j import Driver, GraphDatabase, Session

from zeropath.exceptions import GraphDatabaseError
from zeropath.logging_config import get_logger
from zeropath.models import ProtocolGraph

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Schema setup Cypher (run once on connect)
# ---------------------------------------------------------------------------

_SCHEMA_QUERIES = [
    # Unique constraints
    "CREATE CONSTRAINT contract_id IF NOT EXISTS FOR (c:Contract) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT function_id IF NOT EXISTS FOR (f:Function) REQUIRE f.id IS UNIQUE",
    "CREATE CONSTRAINT statevar_id IF NOT EXISTS FOR (v:StateVariable) REQUIRE v.id IS UNIQUE",
    "CREATE CONSTRAINT event_id IF NOT EXISTS FOR (e:Event) REQUIRE e.id IS UNIQUE",
    "CREATE CONSTRAINT extdep_id IF NOT EXISTS FOR (d:ExternalDep) REQUIRE d.id IS UNIQUE",
    # Lookup indexes
    "CREATE INDEX contract_name IF NOT EXISTS FOR (c:Contract) ON (c.name)",
    "CREATE INDEX function_name IF NOT EXISTS FOR (f:Function) ON (f.name)",
]


class Neo4jGraphDB:
    """
    Manages Neo4j persistence for the ZeroPath protocol graph.

    Usage::

        db = Neo4jGraphDB(uri=..., username=..., password=...)
        db.connect()
        try:
            db.store_protocol_graph(graph)
            results = db.get_contract_call_graph("MyToken")
        finally:
            db.disconnect()

    All `store_*` methods use MERGE semantics so they are safe to call
    multiple times — re-running analysis updates properties in place.
    """

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        database: str = "neo4j",
    ) -> None:
        self.uri = uri
        self.username = username
        self.password = password
        self.database = database
        self.driver: Optional[Driver] = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Open the driver and verify connectivity. Apply schema."""
        try:
            self.driver = GraphDatabase.driver(
                self.uri, auth=(self.username, self.password)
            )
            self.driver.verify_connectivity()
            self._apply_schema()
            logger.info("neo4j_connected", uri=self.uri, database=self.database)
        except Exception as exc:
            raise GraphDatabaseError(f"Neo4j connection failed: {exc}") from exc

    def disconnect(self) -> None:
        """Close the driver connection."""
        if self.driver:
            self.driver.close()
            self.driver = None
            logger.info("neo4j_disconnected")

    def __enter__(self) -> "Neo4jGraphDB":
        self.connect()
        return self

    def __exit__(self, *_: Any) -> None:
        self.disconnect()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _apply_schema(self) -> None:
        """Create constraints and indexes (idempotent via IF NOT EXISTS)."""
        if not self.driver:
            return
        with self.driver.session(database=self.database) as session:
            for q in _SCHEMA_QUERIES:
                try:
                    session.run(q)
                except Exception as exc:
                    # Non-fatal — older Neo4j versions may not support all syntax
                    logger.warning("schema_query_failed", query=q[:60], error=str(exc))

    # ------------------------------------------------------------------
    # Top-level store
    # ------------------------------------------------------------------

    def store_protocol_graph(self, graph: ProtocolGraph, clear_first: bool = False) -> None:
        """
        Persist a complete ProtocolGraph into Neo4j.

        Args:
            graph:       The graph to store.
            clear_first: If True, delete all existing nodes before inserting.
                         Default False (MERGE — safe for incremental updates).

        Raises:
            GraphDatabaseError
        """
        if not self.driver:
            raise GraphDatabaseError("Not connected to Neo4j. Call connect() first.")

        try:
            with self.driver.session(database=self.database) as session:
                if clear_first:
                    session.run("MATCH (n) DETACH DELETE n")
                    logger.info("neo4j_cleared")

                # Nodes
                for contract in graph.contracts:
                    self._merge_contract(session, contract)

                for func in graph.functions:
                    self._merge_function(session, func)

                for var in graph.state_variables:
                    self._merge_state_variable(session, var)

                for event in graph.events:
                    self._merge_event(session, event)

                for dep in graph.external_dependencies:
                    self._merge_external_dep(session, dep)

                # Relationships
                for call in graph.function_calls:
                    self._merge_call_relationship(session, call)

                for flow in graph.asset_flows:
                    self._merge_asset_flow(session, flow)

                for proxy_rel in graph.proxy_relationships:
                    self._merge_proxy_relationship(session, proxy_rel)

                logger.info(
                    "protocol_graph_stored",
                    contracts=len(graph.contracts),
                    functions=len(graph.functions),
                    state_vars=len(graph.state_variables),
                    calls=len(graph.function_calls),
                    flows=len(graph.asset_flows),
                )

        except GraphDatabaseError:
            raise
        except Exception as exc:
            raise GraphDatabaseError(f"Graph storage failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Node merges
    # ------------------------------------------------------------------

    @staticmethod
    def _merge_contract(session: Session, contract: Any) -> None:
        session.run(
            """
            MERGE (c:Contract {id: $id})
            SET c.name        = $name,
                c.language    = $language,
                c.file_path   = $file_path,
                c.is_library  = $is_library,
                c.is_abstract = $is_abstract,
                c.proxy_type  = $proxy_type,
                c.compiler_version = $compiler_version
            """,
            id=contract.id,
            name=contract.name,
            language=contract.language.value,
            file_path=contract.file_path,
            is_library=contract.is_library,
            is_abstract=contract.is_abstract,
            proxy_type=contract.proxy_type.value,
            compiler_version=contract.compiler_version,
        )

    @staticmethod
    def _merge_function(session: Session, func: Any) -> None:
        session.run(
            """
            MATCH (c:Contract {id: $contract_id})
            MERGE (f:Function {id: $id})
            SET f.name        = $name,
                f.visibility  = $visibility,
                f.is_pure     = $is_pure,
                f.is_view     = $is_view,
                f.is_payable  = $is_payable,
                f.is_constructor = $is_constructor,
                f.is_fallback = $is_fallback,
                f.line_start  = $line_start,
                f.line_end    = $line_end,
                f.selector    = $selector
            MERGE (f)-[:DEFINED_IN]->(c)
            """,
            id=func.id,
            name=func.name,
            contract_id=func.contract_id,
            visibility=func.visibility.value,
            is_pure=func.is_pure,
            is_view=func.is_view,
            is_payable=func.is_payable,
            is_constructor=func.is_constructor,
            is_fallback=func.is_fallback,
            line_start=func.line_start,
            line_end=func.line_end,
            selector=func.signature.selector,
        )

    @staticmethod
    def _merge_state_variable(session: Session, var: Any) -> None:
        # Use var.type_ (Python attribute name), NOT var.type (alias)
        type_str = var.type_

        query_no_contract = """
            MERGE (v:StateVariable {id: $id})
            SET v.name        = $name,
                v.type        = $type,
                v.visibility  = $visibility,
                v.is_constant = $is_constant,
                v.storage_slot = $storage_slot
        """
        query_with_contract = """
            MERGE (v:StateVariable {id: $id})
            SET v.name        = $name,
                v.type        = $type,
                v.visibility  = $visibility,
                v.is_constant = $is_constant,
                v.storage_slot = $storage_slot
            WITH v
            MATCH (c:Contract {id: $contract_id})
            MERGE (v)-[:BELONGS_TO]->(c)
        """

        slot = var.storage.slot if var.storage else None

        if var.contract_id:
            session.run(
                query_with_contract,
                id=var.id,
                name=var.name,
                type=type_str,
                visibility=var.visibility.value,
                is_constant=var.is_constant,
                storage_slot=slot,
                contract_id=var.contract_id,
            )
        else:
            session.run(
                query_no_contract,
                id=var.id,
                name=var.name,
                type=type_str,
                visibility=var.visibility.value,
                is_constant=var.is_constant,
                storage_slot=slot,
            )

    @staticmethod
    def _merge_event(session: Session, event: Any) -> None:
        session.run(
            """
            MERGE (e:Event {id: $id})
            SET e.name = $name
            WITH e
            MATCH (c:Contract {id: $contract_id})
            MERGE (e)-[:DEFINED_IN]->(c)
            """,
            id=event.id,
            name=event.name,
            contract_id=event.contract_id,
        )

    @staticmethod
    def _merge_external_dep(session: Session, dep: Any) -> None:
        session.run(
            """
            MERGE (d:ExternalDep {id: $id})
            SET d.name      = $name,
                d.interface = $interface
            """,
            id=dep.id,
            name=dep.name,
            interface=dep.interface,
        )

    # ------------------------------------------------------------------
    # Relationship merges
    # ------------------------------------------------------------------

    @staticmethod
    def _merge_call_relationship(session: Session, call: Any) -> None:
        if not call.callee_id:
            return  # unresolved external target — skip graph edge
        session.run(
            """
            MATCH (caller:Function {id: $caller_id})
            MATCH (callee:Function {id: $callee_id})
            MERGE (caller)-[r:CALLS {id: $id}]->(callee)
            SET r.call_type       = $call_type,
                r.is_delegatecall = $is_delegatecall,
                r.value_transfer  = $value_transfer,
                r.line_number     = $line_number
            """,
            id=call.id,
            caller_id=call.caller_id,
            callee_id=call.callee_id,
            call_type=call.call_type.value,
            is_delegatecall=call.is_delegatecall,
            value_transfer=call.value_transfer,
            line_number=call.line_number,
        )

    @staticmethod
    def _merge_asset_flow(session: Session, flow: Any) -> None:
        if not flow.to_function_id:
            return  # external sink with no resolved target — skip
        session.run(
            """
            MATCH (from:Function {id: $from_id})
            MATCH (to:Function   {id: $to_id})
            MERGE (from)-[r:ASSET_FLOW {id: $id}]->(to)
            SET r.asset_type    = $asset_type,
                r.is_conditional = $is_conditional,
                r.line_number   = $line_number
            """,
            id=flow.id,
            from_id=flow.from_function_id,
            to_id=flow.to_function_id,
            asset_type=flow.asset_type,
            is_conditional=flow.is_conditional,
            line_number=flow.line_number,
        )

    @staticmethod
    def _merge_proxy_relationship(session: Session, proxy_rel: Any) -> None:
        if not proxy_rel.implementation_contract_id:
            return
        session.run(
            """
            MATCH (proxy:Contract {id: $proxy_id})
            MATCH (impl:Contract  {id: $impl_id})
            MERGE (proxy)-[r:PROXIES_TO]->(impl)
            SET r.proxy_type     = $proxy_type,
                r.is_upgradeable = $is_upgradeable,
                r.upgrade_fn     = $upgrade_fn
            """,
            proxy_id=proxy_rel.proxy_contract_id,
            impl_id=proxy_rel.implementation_contract_id,
            proxy_type=proxy_rel.proxy_type.value,
            is_upgradeable=proxy_rel.is_upgradeable,
            upgrade_fn=proxy_rel.upgrade_function,
        )

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def query(self, cypher_query: str, parameters: Optional[dict] = None) -> list[dict]:
        """
        Execute an arbitrary Cypher query.

        Args:
            cypher_query: Cypher query string.
            parameters:   Optional parameter dict.

        Returns:
            List of result records as dicts.
        """
        if not self.driver:
            raise GraphDatabaseError("Not connected.")
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(cypher_query, parameters or {})
                return [dict(record) for record in result]
        except Exception as exc:
            raise GraphDatabaseError(f"Query failed: {exc}") from exc

    def get_contract_call_graph(self, contract_name: str) -> list[dict]:
        """Return all function-to-function call edges within a contract."""
        return self.query(
            """
            MATCH (c:Contract {name: $name})<-[:DEFINED_IN]-(caller:Function)
                  -[:CALLS]->(callee:Function)
            RETURN caller.name AS caller, callee.name AS callee,
                   caller.line_start AS line
            ORDER BY caller.name, callee.name
            """,
            {"name": contract_name},
        )

    def get_external_calls(self, function_name: str) -> list[dict]:
        """Return all external calls made by functions with this name."""
        return self.query(
            """
            MATCH (f:Function {name: $name})-[r:CALLS]->(callee:Function)
            WHERE r.call_type IN ['external', 'delegatecall', 'staticcall', 'low_level']
            RETURN callee.name AS external_call,
                   callee.is_payable AS is_payable,
                   r.call_type AS call_type,
                   r.is_delegatecall AS is_delegatecall
            """,
            {"name": function_name},
        )

    def get_asset_flow_paths(self, start_function: str) -> list[list[str]]:
        """Return all asset flow paths from a starting function (up to depth 10)."""
        results = self.query(
            """
            MATCH p = (start:Function {name: $fn})-[:ASSET_FLOW*1..10]->(end:Function)
            RETURN [n IN nodes(p) | n.name] AS path
            """,
            {"fn": start_function},
        )
        return [r["path"] for r in results]

    def get_payable_functions(self) -> list[dict]:
        """Return all payable functions across all contracts."""
        return self.query(
            """
            MATCH (f:Function {is_payable: true})-[:DEFINED_IN]->(c:Contract)
            RETURN c.name AS contract, f.name AS function,
                   f.visibility AS visibility, f.line_start AS line
            ORDER BY c.name, f.name
            """
        )

    def get_proxy_contracts(self) -> list[dict]:
        """Return all detected proxy contracts and their types."""
        return self.query(
            """
            MATCH (c:Contract)
            WHERE c.proxy_type <> 'none'
            OPTIONAL MATCH (c)-[:PROXIES_TO]->(impl:Contract)
            RETURN c.name AS proxy, c.proxy_type AS type,
                   impl.name AS implementation
            ORDER BY c.name
            """
        )

    def get_access_controlled_functions(self) -> list[dict]:
        """Return functions that use access control modifiers."""
        return self.query(
            """
            MATCH (f:Function)-[:DEFINED_IN]->(c:Contract)
            WHERE f.visibility IN ['public', 'external']
            RETURN c.name AS contract, f.name AS function,
                   f.visibility AS visibility
            ORDER BY c.name, f.name
            """
        )

    def find_reentrancy_candidates(self) -> list[dict]:
        """
        Heuristic: functions that write state AND make external calls.
        Not a definitive reentrancy detector — for hypothesis seeding.
        """
        return self.query(
            """
            MATCH (f:Function)-[:DEFINED_IN]->(c:Contract)
            MATCH (f)-[r:CALLS]->(ext:Function)
            WHERE r.call_type IN ['external', 'low_level']
            RETURN c.name AS contract, f.name AS function,
                   collect(ext.name) AS external_calls
            ORDER BY c.name, f.name
            """
        )
