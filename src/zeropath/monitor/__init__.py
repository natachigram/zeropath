"""
Phase 10: Real-Time On-Chain Monitor.

Defensive flip-side of Phases 1-9. Reuses the Phase 8 knowledge graph as a
detection rule set, watches the mempool, and fires alerts to Discord /
Slack / PagerDuty when a pending tx matches a known exploit pattern.

Public API::

    from zeropath.monitor import RealTimeMonitor

    monitor = RealTimeMonitor(knowledge=kg)            # uses env-driven dispatcher
    report = monitor.run(max_seconds=600)              # watch for 10 minutes
    print(report.health.alerts_dispatched)
"""

from zeropath.monitor.alerts import (
    AlertDispatcher,
    BaseAlertSink,
    DiscordSink,
    DispatchResult,
    DispatchSummary,
    GenericWebhookSink,
    PagerDutySink,
    SlackSink,
    StdoutSink,
    build_default_dispatcher,
)
from zeropath.monitor.classifier import TxClassifier
from zeropath.monitor.dashboard import ProtocolHealthDashboard
from zeropath.monitor.mempool import (
    BaseSubscriber,
    JsonRpcPollingSubscriber,
    MempoolError,
    SyntheticSubscriber,
    WebSocketSubscriber,
)
from zeropath.monitor.models import (
    AlertChannel,
    AlertEvent,
    AlertSeverity,
    HealthSnapshot,
    MagnitudeBand,
    MatchKind,
    MempoolSource,
    MempoolTx,
    MonitorReport,
    PatternSignature,
    SignatureMatch,
)
from zeropath.monitor.monitor import RealTimeMonitor
from zeropath.monitor.pattern_matcher import PatternMatcher
from zeropath.monitor.signatures import SignatureExtractor

__all__ = [
    # Orchestrator
    "RealTimeMonitor",
    # Components
    "SignatureExtractor",
    "TxClassifier", "PatternMatcher",
    "AlertDispatcher",
    "BaseAlertSink", "DiscordSink", "SlackSink", "PagerDutySink",
    "StdoutSink", "GenericWebhookSink",
    "DispatchResult", "DispatchSummary",
    "build_default_dispatcher",
    "ProtocolHealthDashboard",
    # Mempool
    "BaseSubscriber", "JsonRpcPollingSubscriber",
    "SyntheticSubscriber", "WebSocketSubscriber", "MempoolError",
    # Models
    "AlertEvent", "AlertSeverity", "AlertChannel",
    "MempoolTx", "MempoolSource",
    "PatternSignature", "MagnitudeBand", "SignatureMatch", "MatchKind",
    "HealthSnapshot", "MonitorReport",
]
