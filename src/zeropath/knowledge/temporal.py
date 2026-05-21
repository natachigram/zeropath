"""
Temporal pattern analyzer — Phase 8.

Spec (phases.md, PHASE 8 critical additions, "Temporal pattern analysis"):
    "Track when vulnerabilities were introduced relative to protocol
     upgrades. The pattern 'upgrade → new vulnerability within 30 days'
     is a real signal. Store version diff data from Phase 1 and correlate
     with exploit discovery timestamps."

This module reads :class:`UpgradeEvent` + :class:`ValidatedExploit` /
:class:`ExternalIncident` nodes from the KG and answers questions like
"how soon after an upgrade did exploitation start?" so audit reports can
call out high-risk windows.

Pure stdlib (``datetime``) — no pandas / no numpy.
"""

from __future__ import annotations

import logging
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional

from zeropath.knowledge.models import KGNode
from zeropath.knowledge.schema import NodeLabel, RelationshipType
from zeropath.knowledge.store import KGStore

logger = logging.getLogger(__name__)


# A vulnerability surfaced within this many days of an upgrade is
# flagged as "post-upgrade exposure".
DEFAULT_POST_UPGRADE_WINDOW_DAYS = 30


# ---------------------------------------------------------------------------
# Result records
# ---------------------------------------------------------------------------


@dataclass
class UpgradeExposure:
    """One (upgrade, follow-on) pairing."""

    upgrade_id: str
    upgrade_date: str
    exploit_id: str
    exploit_date: str
    days_after_upgrade: int
    within_window: bool


@dataclass
class TemporalSummary:
    """Aggregate statistics over all exposures for one protocol."""

    protocol_name: str
    upgrades: int = 0
    exposures: int = 0
    exposures_within_window: int = 0
    median_days_to_exploit: Optional[float] = None
    earliest_days_to_exploit: Optional[int] = None
    window_days: int = DEFAULT_POST_UPGRADE_WINDOW_DAYS
    samples: list[UpgradeExposure] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


class TemporalAnalyzer:
    """
    Read the KG, compute upgrade-vs-exploit timing per protocol.

    Parameters
    ----------
    store : KGStore
        Backend to read from.
    window_days : int
        "Post-upgrade exposure window" — exploits that land within this many
        days of an upgrade get the high-risk flag.
    """

    def __init__(
        self,
        store: KGStore,
        *,
        window_days: int = DEFAULT_POST_UPGRADE_WINDOW_DAYS,
    ) -> None:
        self.store = store
        self.window_days = window_days

    # ------------------------------------------------------------------
    # Per-protocol summary
    # ------------------------------------------------------------------

    def summarise(self, protocol_name: str) -> TemporalSummary:
        protocol_nodes = self.store.find_by_property(
            NodeLabel.PROTOCOL, "name", protocol_name
        )
        if not protocol_nodes:
            return TemporalSummary(
                protocol_name=protocol_name, window_days=self.window_days,
            )
        protocol = protocol_nodes[0]
        upgrades = self._upgrades_for(protocol)
        exploits = self._exploits_for(protocol_name)

        exposures: list[UpgradeExposure] = []
        for ex in exploits:
            ex_dt = _parse_iso(self._exploit_timestamp(ex))
            if not ex_dt:
                continue
            for up in upgrades:
                up_dt = _parse_iso(up.properties.get("upgrade_date"))
                if not up_dt or ex_dt < up_dt:
                    continue
                delta = (ex_dt - up_dt).days
                exposures.append(UpgradeExposure(
                    upgrade_id=up.id,
                    upgrade_date=up.properties.get("upgrade_date", ""),
                    exploit_id=ex.id,
                    exploit_date=self._exploit_timestamp(ex) or "",
                    days_after_upgrade=delta,
                    within_window=delta <= self.window_days,
                ))

        deltas = [e.days_after_upgrade for e in exposures]
        summary = TemporalSummary(
            protocol_name=protocol_name,
            upgrades=len(upgrades),
            exposures=len(exposures),
            exposures_within_window=sum(1 for e in exposures if e.within_window),
            window_days=self.window_days,
            samples=exposures,
        )
        if deltas:
            summary.median_days_to_exploit = round(statistics.median(deltas), 2)
            summary.earliest_days_to_exploit = min(deltas)
        return summary

    # ------------------------------------------------------------------
    # Population-level rollup
    # ------------------------------------------------------------------

    def overall_post_upgrade_risk(self) -> float:
        """
        Fraction of (upgrade, exploit) pairs that fell within
        ``window_days``. This is the headline "upgrade → new vulnerability"
        risk number the spec calls out.
        """
        total = 0
        in_window = 0
        for protocol in self.store.find_by_label(NodeLabel.PROTOCOL):
            name = protocol.properties.get("name")
            if not name:
                continue
            summary = self.summarise(name)
            total += summary.exposures
            in_window += summary.exposures_within_window
        if total == 0:
            return 0.0
        return round(in_window / total, 4)

    def all_summaries(self) -> list[TemporalSummary]:
        """One TemporalSummary per protocol seen in the KG."""
        out: list[TemporalSummary] = []
        for protocol in self.store.find_by_label(NodeLabel.PROTOCOL):
            name = protocol.properties.get("name")
            if not name:
                continue
            out.append(self.summarise(name))
        return out

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _upgrades_for(self, protocol: KGNode) -> list[KGNode]:
        upgrades: list[KGNode] = []
        for _edge, neighbor in self.store.neighbors(
            protocol.id, rel_type=RelationshipType.CONTAINS, direction="out",
        ):
            if neighbor.label == NodeLabel.UPGRADE_EVENT:
                upgrades.append(neighbor)
        return upgrades

    def _exploits_for(self, protocol_name: str) -> list[KGNode]:
        out: list[KGNode] = []
        for ex in self.store.find_by_label(NodeLabel.VALIDATED_EXPLOIT):
            if ex.properties.get("protocol_name") == protocol_name:
                out.append(ex)
        for inc in self.store.find_by_label(NodeLabel.EXTERNAL_INCIDENT):
            if inc.properties.get("protocol") == protocol_name:
                out.append(inc)
        return out

    @staticmethod
    def _exploit_timestamp(node: KGNode) -> Optional[str]:
        # Validated exploits carry recorded_at; external incidents carry incident_date.
        return (
            node.properties.get("recorded_at")
            or node.properties.get("incident_date")
        )
