"""
Pydantic models for Phase 10: Real-Time On-Chain Monitor.

The monitor inverts the offensive pipeline — every artefact the earlier
phases produced (KG nodes, validated exploits, threat intel) becomes a
*signature* the live mempool is checked against. When a pending tx
matches, an alert fires.

Shared with the Phase 9 reporting layer in spirit but kept narrowly typed
for the low-latency hot path.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AlertSeverity(str, Enum):
    """Severity tiers driving channel routing + PagerDuty `severity`."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def pagerduty(self) -> str:
        """Map to PagerDuty's accepted severity values."""
        return {
            AlertSeverity.CRITICAL: "critical",
            AlertSeverity.HIGH: "error",
            AlertSeverity.MEDIUM: "warning",
            AlertSeverity.LOW: "info",
            AlertSeverity.INFORMATIONAL: "info",
        }[self]

    @property
    def slack_color(self) -> str:
        return {
            AlertSeverity.CRITICAL: "danger",
            AlertSeverity.HIGH: "danger",
            AlertSeverity.MEDIUM: "warning",
            AlertSeverity.LOW: "good",
            AlertSeverity.INFORMATIONAL: "good",
        }[self]

    @property
    def discord_color(self) -> int:
        """Decimal RGB for Discord embed colors."""
        return {
            AlertSeverity.CRITICAL: 0xB71C1C,
            AlertSeverity.HIGH: 0xE65100,
            AlertSeverity.MEDIUM: 0xFBC02D,
            AlertSeverity.LOW: 0x388E3C,
            AlertSeverity.INFORMATIONAL: 0x1976D2,
        }[self]


class AlertChannel(str, Enum):
    DISCORD = "discord"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    STDOUT = "stdout"           # always-on dev sink
    WEBHOOK = "webhook"         # generic JSON POST


class MempoolSource(str, Enum):
    """Where pending txs arrive from."""

    JSON_RPC_POLL = "json_rpc_poll"
    WEBSOCKET_SUBSCRIBE = "websocket_subscribe"
    SYNTHETIC = "synthetic"     # test / replay


class MatchKind(str, Enum):
    """Why a pending tx scored against a signature."""

    SELECTOR = "selector"
    TARGET_ADDRESS = "target_address"
    PROTOCOL = "protocol"
    MAGNITUDE = "magnitude"
    CONTEXT = "context"
    COMPOSITE = "composite"


# ---------------------------------------------------------------------------
# Mempool transaction
# ---------------------------------------------------------------------------


class MempoolTx(BaseModel):
    """
    Compact view of one pending transaction.

    Populated by :class:`MempoolSubscriber` from the raw JSON-RPC payload
    (or a synthetic source in tests). The classifier never reads the raw
    JSON — it sees only this typed view.
    """

    model_config = ConfigDict(populate_by_name=True)

    tx_hash: str = ""
    chain_id: int = 1

    from_address: str = ""
    to_address: Optional[str] = None    # None = contract creation
    value_wei: int = 0

    input_hex: str = "0x"
    function_selector: Optional[str] = Field(
        None, description="Lowercase 0x-prefixed 4-byte selector, derived from input_hex.",
    )

    nonce: Optional[int] = None
    gas_limit: Optional[int] = None
    gas_price_wei: Optional[int] = None
    max_fee_per_gas_wei: Optional[int] = None
    max_priority_fee_per_gas_wei: Optional[int] = None

    seen_at: str = Field(default_factory=_utc_now)
    source: MempoolSource = MempoolSource.JSON_RPC_POLL


# ---------------------------------------------------------------------------
# Pattern signature
# ---------------------------------------------------------------------------


class MagnitudeBand(BaseModel):
    """
    Optional value band for catching unusually-large parameter / value moves.

    A pending tx whose ``value_wei`` (or first inferred amount param) lies
    inside ``[min_wei, max_wei]`` is treated as in-band.
    """

    model_config = ConfigDict(populate_by_name=True)

    min_wei: int = 0
    max_wei: int = 2**256 - 1


class PatternSignature(BaseModel):
    """
    Compiled detection rule. Derived from Phase 8 KG nodes or supplied
    manually for protocol-specific rules.

    Matching is *additive*: each non-None field contributes to the score;
    None means "don't constrain this dimension".
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    attack_class: str
    protocol_name: Optional[str] = None

    # Dimensions checked at match time
    function_selectors: list[str] = Field(
        default_factory=list,
        description="Lowercase 0x-prefixed selectors that flag this signature.",
    )
    target_addresses: list[str] = Field(
        default_factory=list,
        description="Lowercase addresses; empty = match any target.",
    )
    value_band: Optional[MagnitudeBand] = None
    required_function_keywords: list[str] = Field(
        default_factory=list,
        description="Keywords searched against decoded function names (best-effort).",
    )

    # Severity + scoring
    base_severity: AlertSeverity = AlertSeverity.MEDIUM
    match_threshold: float = Field(
        0.5, ge=0.0, le=1.0,
        description="Below this score the signature does not produce an alert.",
    )

    # Provenance back to the KG
    source_node_id: Optional[str] = None
    source_kind: str = "manual"          # "exploit_pattern" | "external_incident" | "validated_exploit" | "manual"
    historical_loss_usd: int = 0


# ---------------------------------------------------------------------------
# Match + alert event
# ---------------------------------------------------------------------------


class SignatureMatch(BaseModel):
    """Per-dimension scoring breakdown for one (tx, signature) pair."""

    model_config = ConfigDict(populate_by_name=True)

    signature_id: str
    signature_name: str
    tx_hash: str
    score: float = Field(0.0, ge=0.0, le=1.0)
    components: dict[str, float] = Field(default_factory=dict)
    matched_dimensions: list[MatchKind] = Field(default_factory=list)


class AlertEvent(BaseModel):
    """
    One alert ready to dispatch. Carries everything the downstream sinks
    need so they don't have to re-query the KG.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    detected_at: str = Field(default_factory=_utc_now)

    severity: AlertSeverity = AlertSeverity.MEDIUM
    title: str
    summary: str
    description: str = ""

    tx: MempoolTx
    match: SignatureMatch
    attack_class: str = "unknown"
    protocol_name: Optional[str] = None
    estimated_loss_usd: int = 0

    # Downstream routing hints
    channels: list[AlertChannel] = Field(default_factory=list)
    dedup_key: str = ""
    explorer_url: Optional[str] = Field(
        None,
        description="https://etherscan.io/tx/0x… style link when known.",
    )

    extra: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Health dashboard records
# ---------------------------------------------------------------------------


class HealthSnapshot(BaseModel):
    """Point-in-time roll-up emitted by :class:`ProtocolHealthDashboard`."""

    model_config = ConfigDict(populate_by_name=True)

    snapshot_at: str = Field(default_factory=_utc_now)
    txs_observed: int = 0
    txs_classified: int = 0
    matches_found: int = 0
    alerts_dispatched: int = 0
    alerts_by_severity: dict[str, int] = Field(default_factory=dict)
    alerts_by_attack_class: dict[str, int] = Field(default_factory=dict)
    top_signatures: list[tuple[str, int]] = Field(default_factory=list)
    last_alert_at: Optional[str] = None
    uptime_seconds: float = 0.0


class MonitorReport(BaseModel):
    """Aggregated output of one ``RealTimeMonitor.run_until(...)`` call."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    started_at: str = Field(default_factory=_utc_now)
    ended_at: Optional[str] = None
    duration_seconds: float = 0.0

    alerts: list[AlertEvent] = Field(default_factory=list)
    health: HealthSnapshot = Field(default_factory=HealthSnapshot)
    analysis_metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def critical_alerts(self) -> list[AlertEvent]:
        return [a for a in self.alerts if a.severity == AlertSeverity.CRITICAL]
