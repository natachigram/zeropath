"""
MCP resource handlers — readable data exposed to the IDE agent.

Two kinds:

  * Static :class:`Resource` — fixed URIs (``zeropath://kg/summary``,
    ``zeropath://contest/last-report``).
  * Dynamic :class:`ResourceTemplate` — URI templates with placeholders
    (``zeropath://kg/findings/{id}``).

Each handler returns a JSON-serialisable dict that the server coerces
into the MCP resource ``contents`` shape.
"""

from __future__ import annotations

import logging
from typing import Any

from zeropath.mcp_server.server import Resource, ResourceTemplate

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Static resources
# ---------------------------------------------------------------------------


def _resource_kg_summary(state) -> Resource:
    def handler(uri: str) -> dict[str, Any]:
        kg = state.ensure_knowledge()
        report = kg.report(protocol_name="all")
        return {
            "exploits_ingested": report.exploits_ingested,
            "incidents_ingested": report.incidents_ingested,
            "inferences_recorded": report.inferences_recorded,
            "accuracy_metrics": [
                m.model_dump(mode="json") for m in report.accuracy_metrics
            ],
            "metadata": report.analysis_metadata,
        }

    return Resource(
        uri="zeropath://kg/summary",
        name="Knowledge graph summary",
        description="Top-level counts of validated exploits, external incidents, and accuracy metrics.",
        handler=handler,
    )


def _resource_kg_findings_index(state) -> Resource:
    def handler(uri: str) -> list[dict[str, Any]]:
        from zeropath.knowledge.schema import NodeLabel
        kg = state.ensure_knowledge()
        out: list[dict[str, Any]] = []
        for node in kg.store.find_by_label(NodeLabel.VALIDATED_EXPLOIT):
            props = node.properties
            out.append({
                "id": node.id,
                "protocol_name": props.get("protocol_name"),
                "attack_class": props.get("attack_class"),
                "severity_tier": props.get("severity_tier"),
                "profit_usd": props.get("profit_usd"),
                "fingerprint": props.get("fingerprint"),
                "uri": f"zeropath://kg/findings/{node.id}",
            })
        return out

    return Resource(
        uri="zeropath://kg/findings",
        name="Knowledge graph — validated findings index",
        description="List of all validated exploits in the KG (id + summary fields).",
        handler=handler,
    )


def _resource_kg_incidents_index(state) -> Resource:
    def handler(uri: str) -> list[dict[str, Any]]:
        from zeropath.knowledge.schema import NodeLabel
        kg = state.ensure_knowledge()
        out: list[dict[str, Any]] = []
        for node in kg.store.find_by_label(NodeLabel.EXTERNAL_INCIDENT):
            props = node.properties
            out.append({
                "id": node.id,
                "protocol": props.get("protocol"),
                "incident_date": props.get("incident_date"),
                "loss_usd": props.get("loss_usd"),
                "attack_class": props.get("attack_class"),
                "source": props.get("source"),
                "uri": f"zeropath://kg/incidents/{node.id}",
            })
        return out

    return Resource(
        uri="zeropath://kg/incidents",
        name="Knowledge graph — historical incidents index",
        description="All external threat-intel incidents (DeFiHackLabs / Rekt / Immunefi).",
        handler=handler,
    )


def _resource_contest_report(state) -> Resource:
    def handler(uri: str) -> dict[str, Any]:
        if state.last_contest_report is None:
            return {"error": "no contest pipeline has been run this session"}
        return state.last_contest_report.model_dump(mode="json")

    return Resource(
        uri="zeropath://contest/last-report",
        name="Last contest report",
        description="Most recent ContestReport (submissions + telemetry).",
        handler=handler,
    )


def _resource_protocol_graph(state) -> Resource:
    def handler(uri: str) -> dict[str, Any]:
        if state.last_protocol_graph is None:
            return {"error": "no graph loaded — call analyze_protocol first"}
        return state.last_protocol_graph.model_dump(mode="json")

    return Resource(
        uri="zeropath://graph/latest",
        name="Latest protocol graph",
        description="Phase 1 ProtocolGraph from the most recent analyze_protocol call.",
        handler=handler,
    )


def _resource_invariant_report(state) -> Resource:
    def handler(uri: str) -> dict[str, Any]:
        if state.last_invariant_report is None:
            return {"error": "no invariants inferred — call infer_invariants first"}
        return state.last_invariant_report.model_dump(mode="json")

    return Resource(
        uri="zeropath://invariants/latest",
        name="Latest invariant report",
        description="Phase 2 InvariantReport from the most recent infer_invariants call.",
        handler=handler,
    )


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------


def _template_kg_finding(state) -> ResourceTemplate:
    def handler(uri: str, params: dict[str, str]) -> dict[str, Any]:
        node_id = params.get("id", "")
        kg = state.ensure_knowledge()
        node = kg.store.get_node(node_id)
        if node is None:
            return {"error": f"no node found for id={node_id}"}
        return node.model_dump(mode="json")

    return ResourceTemplate(
        uri_template="zeropath://kg/findings/{id}",
        name="Knowledge graph finding by id",
        description="Fetch one validated-exploit node by its KG id.",
        handler=handler,
    )


def _template_kg_incident(state) -> ResourceTemplate:
    def handler(uri: str, params: dict[str, str]) -> dict[str, Any]:
        node_id = params.get("id", "")
        kg = state.ensure_knowledge()
        node = kg.store.get_node(node_id)
        if node is None:
            return {"error": f"no node found for id={node_id}"}
        return node.model_dump(mode="json")

    return ResourceTemplate(
        uri_template="zeropath://kg/incidents/{id}",
        name="Historical incident by id",
        description="Fetch one external-incident node by its KG id.",
        handler=handler,
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_default_resources(server, state) -> None:
    """Wire every default resource + template onto the server."""
    for build in (
        _resource_kg_summary,
        _resource_kg_findings_index,
        _resource_kg_incidents_index,
        _resource_contest_report,
        _resource_protocol_graph,
        _resource_invariant_report,
    ):
        server.add_resource(build(state))

    for build_template in (
        _template_kg_finding,
        _template_kg_incident,
    ):
        server.add_resource_template(build_template(state))
