"""
Knowledge-graph node + relationship constants — Phase 8.

These string constants are the source of truth for the KG schema. Storing
them in one module lets the Cypher-emitting :class:`Neo4jKGStore` and the
:class:`InMemoryKGStore` index over the same labels, and lets the
:class:`SimilarityEngine` query without re-typing the strings.

Schema (Neo4j-style label/relationship naming):

    Nodes
    -----
    ExploitPattern    — a generalised exploit class (oracle, reentrancy, …)
    ValidatedExploit  — a single Phase 6 ValidationResult that surfaced
    Invariant         — a Phase 2 invariant referenced by exploits
    Protocol          — a protocol the graph has analysed
    Function          — a function inside a Protocol (link target for exploits)
    StateVariable     — a state var inside a Protocol
    ExternalIncident  — a real-world historical incident from threat intel
    UpgradeEvent      — a protocol version diff (Phase 1 version-diff mode)
    Inference         — a prediction made by an earlier phase (for accuracy)

    Relationships
    -------------
    EXPLOITS         — ValidatedExploit -> Protocol
    INSTANCE_OF      — ValidatedExploit -> ExploitPattern
    VIOLATES         — ValidatedExploit -> Invariant
    LINKED_TO        — Invariant -> ExternalIncident
    RESEMBLES        — Protocol -> Protocol (graph-similarity edges)
    INTRODUCED_IN    — Invariant -> UpgradeEvent
    PRECEDED_BY      — ExternalIncident -> ExternalIncident (chronology)
    VALIDATED        — Inference -> ValidatedExploit (positive outcome)
    INVALIDATED      — Inference -> ValidationResult (negative outcome)
    CONTAINS         — Protocol -> {Function | StateVariable}
"""

from __future__ import annotations

from enum import Enum


class NodeLabel(str, Enum):
    EXPLOIT_PATTERN = "ExploitPattern"
    VALIDATED_EXPLOIT = "ValidatedExploit"
    INVARIANT = "Invariant"
    PROTOCOL = "Protocol"
    FUNCTION = "Function"
    STATE_VARIABLE = "StateVariable"
    EXTERNAL_INCIDENT = "ExternalIncident"
    UPGRADE_EVENT = "UpgradeEvent"
    INFERENCE = "Inference"


class RelationshipType(str, Enum):
    EXPLOITS = "EXPLOITS"
    INSTANCE_OF = "INSTANCE_OF"
    VIOLATES = "VIOLATES"
    LINKED_TO = "LINKED_TO"
    RESEMBLES = "RESEMBLES"
    INTRODUCED_IN = "INTRODUCED_IN"
    PRECEDED_BY = "PRECEDED_BY"
    VALIDATED = "VALIDATED"
    INVALIDATED = "INVALIDATED"
    CONTAINS = "CONTAINS"


# Cypher schema setup — applied once on connect by Neo4jKGStore.
# Stored here so the in-memory + neo4j stores share an identical assumption
# about what is unique.
SCHEMA_QUERIES: list[str] = [
    "CREATE CONSTRAINT kg_validated_exploit_id IF NOT EXISTS FOR (e:ValidatedExploit) REQUIRE e.id IS UNIQUE",
    "CREATE CONSTRAINT kg_invariant_id IF NOT EXISTS FOR (i:Invariant) REQUIRE i.id IS UNIQUE",
    "CREATE CONSTRAINT kg_protocol_name IF NOT EXISTS FOR (p:Protocol) REQUIRE p.name IS UNIQUE",
    "CREATE CONSTRAINT kg_external_incident_id IF NOT EXISTS FOR (x:ExternalIncident) REQUIRE x.id IS UNIQUE",
    "CREATE CONSTRAINT kg_exploit_pattern_class IF NOT EXISTS FOR (p:ExploitPattern) REQUIRE p.attack_class IS UNIQUE",
    "CREATE CONSTRAINT kg_inference_id IF NOT EXISTS FOR (n:Inference) REQUIRE n.id IS UNIQUE",
    "CREATE INDEX kg_validated_exploit_fingerprint IF NOT EXISTS FOR (e:ValidatedExploit) ON (e.fingerprint)",
    "CREATE INDEX kg_external_incident_protocol IF NOT EXISTS FOR (x:ExternalIncident) ON (x.protocol)",
]
