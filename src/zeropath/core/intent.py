"""Protocol intent extraction from adapter output."""

from __future__ import annotations

from zeropath.core.invariants import invariants_for_protocol_type
from zeropath.core.schemas import (
    ExternalDependency,
    ProtocolIntent,
    Role,
    TrustBoundary,
)
from zeropath.core.storage import Storage


def build_protocol_intent(storage: Storage) -> ProtocolIntent:
    """Create a ProtocolIntent snapshot from indexed project data."""

    config = storage.load_project_config()
    index = storage.load_record("ingest", "evm_index") or {}
    contracts = [item.get("name", "") for item in index.get("contracts", []) if item.get("name")]
    protocol_type = index.get("protocol_type") or "unknown"
    roles = [
        Role(
            name=role["name"],
            capabilities=role.get("capabilities", []),
            trust_level=role.get("trust_level", "unknown"),
            source=role.get("source"),
        )
        for role in index.get("roles", [])
    ]
    dependencies = [
        ExternalDependency(
            name=dep["name"],
            dependency_type=dep.get("dependency_type", "external_contract"),
            description=dep.get("description", ""),
            trust_assumption=dep.get("trust_assumption", "must behave as expected"),
            source=dep.get("source"),
        )
        for dep in index.get("external_dependencies", [])
    ]
    boundaries = (
        [
            TrustBoundary(
                name="External calls",
                boundary_type="contract_call",
                description="Calls or token transfers cross out of the indexed codebase.",
                risk="Asset movement and callbacks require proof when used in exploit hypotheses.",
                source="evm heuristic",
            )
        ]
        if dependencies or index.get("asset_flows") or index.get("external_calls")
        else []
    )
    invariants = invariants_for_protocol_type(protocol_type, contracts)
    summary = _summary(protocol_type, contracts, index)
    intent = ProtocolIntent(
        project_id=config.project_id,
        protocol_name=config.metadata.get("protocol_name") or config.project_id,
        protocol_type=protocol_type,
        summary=summary,
        roles=roles,
        trust_boundaries=boundaries,
        external_dependencies=dependencies,
        critical_invariants=invariants,
        assumptions=[
            "Intent is heuristic until confirmed by docs, tests, and maintainer scope.",
            "Generated hypotheses are not findings until judged with evidence.",
        ],
        unknowns=index.get("unknowns", []),
        confidence="inferred",
    )
    storage.save_protocol_intent(intent)
    return intent


def _summary(protocol_type: str, contracts: list[str], index: dict) -> str:
    contract_text = ", ".join(contracts[:5]) if contracts else "no contracts indexed"
    if len(contracts) > 5:
        contract_text += f", and {len(contracts) - 5} more"
    article = "an" if protocol_type[:1].lower() in {"a", "e", "i", "o", "u"} else "a"
    return (
        f"Detected {article} {protocol_type} project from lightweight adapter indexing. "
        f"Indexed contracts: {contract_text}. "
        f"Signals are heuristic and should be confirmed before reporting."
    )
