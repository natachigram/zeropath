"""
RealTimeMonitor — Phase 10 top-level coordinator.

Hot-loop pipeline::

    MempoolSubscriber  →  TxClassifier  →  PatternMatcher
                                                   │
                                                   ▼
                                  build AlertEvent (severity, dedup_key)
                                                   │
                                          AlertDispatcher
                                                   │
                                  ProtocolHealthDashboard (records every step)

The orchestrator is purpose-built to keep latency low: each pending tx is
classified once, scanned against a pre-indexed signature table, and the
alert payload is built inline so the dispatcher can fire while the tx is
still pending.
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Iterable, Optional

from zeropath.knowledge.knowledge import KnowledgeGraphOrchestrator
from zeropath.monitor.alerts import (
    AlertDispatcher,
    DispatchSummary,
    build_default_dispatcher,
)
from zeropath.monitor.classifier import TxClassifier
from zeropath.monitor.dashboard import ProtocolHealthDashboard
from zeropath.monitor.mempool import (
    BaseSubscriber,
    JsonRpcPollingSubscriber,
    MempoolError,
)
from zeropath.monitor.models import (
    AlertEvent,
    AlertSeverity,
    HealthSnapshot,
    MempoolTx,
    MonitorReport,
    PatternSignature,
    SignatureMatch,
)
from zeropath.monitor.pattern_matcher import PatternMatcher
from zeropath.monitor.signatures import SignatureExtractor

logger = logging.getLogger(__name__)


# Per-chain canonical explorer prefix for tx links in alerts.
_EXPLORER_PREFIX: dict[int, str] = {
    1:     "https://etherscan.io/tx/",
    10:    "https://optimistic.etherscan.io/tx/",
    137:   "https://polygonscan.com/tx/",
    42161: "https://arbiscan.io/tx/",
    8453:  "https://basescan.org/tx/",
}


# Match score → alert severity mapping. Signature ``base_severity`` is the
# floor; a strong score lifts the alert one tier.
_STRONG_MATCH_BOOST_THRESHOLD = 0.85


def _resolve_severity(sig: PatternSignature, match: SignatureMatch) -> AlertSeverity:
    base = sig.base_severity
    if match.score < _STRONG_MATCH_BOOST_THRESHOLD:
        return base
    order = [
        AlertSeverity.INFORMATIONAL, AlertSeverity.LOW, AlertSeverity.MEDIUM,
        AlertSeverity.HIGH, AlertSeverity.CRITICAL,
    ]
    idx = order.index(base)
    return order[min(idx + 1, len(order) - 1)]


class RealTimeMonitor:
    """
    End-to-end watchtower around the mempool.

    Parameters
    ----------
    knowledge : KnowledgeGraphOrchestrator | None
        KG source for compiling signatures. ``None`` uses only the
        default per-attack-class signatures.
    extra_signatures : list[PatternSignature] | None
        Manually-curated signatures appended to the compiled list.
    subscriber : BaseSubscriber | None
        Mempool source. ``None`` builds a :class:`JsonRpcPollingSubscriber`
        from ``rpc_url`` / env.
    dispatcher : AlertDispatcher | None
        Alert fan-out. ``None`` reads sinks from env via
        :func:`build_default_dispatcher`.
    dashboard : ProtocolHealthDashboard | None
        Stats sink. A default in-memory dashboard is created when None.
    on_alert : callable | None
        Optional callback invoked after dispatch — useful for tests + KG
        persistence.
    rpc_url : str | None
    chain_id : int
    """

    def __init__(
        self,
        *,
        knowledge: Optional[KnowledgeGraphOrchestrator] = None,
        extra_signatures: Optional[list[PatternSignature]] = None,
        subscriber: Optional[BaseSubscriber] = None,
        dispatcher: Optional[AlertDispatcher] = None,
        dashboard: Optional[ProtocolHealthDashboard] = None,
        on_alert: Optional[Callable[[AlertEvent, DispatchSummary], None]] = None,
        rpc_url: Optional[str] = None,
        chain_id: int = 1,
    ) -> None:
        self.knowledge = knowledge
        self.chain_id = chain_id

        sigs = SignatureExtractor(knowledge=knowledge).extract()
        if extra_signatures:
            sigs.extend(extra_signatures)
        self.signatures = sigs
        self.matcher = PatternMatcher(sigs)
        self.classifier = TxClassifier(chain_id=chain_id)
        self.subscriber = subscriber or self._default_subscriber(rpc_url, chain_id)
        self.dispatcher = dispatcher or build_default_dispatcher()
        self.dashboard = dashboard or ProtocolHealthDashboard()
        self.on_alert = on_alert

        self._started_at: Optional[float] = None
        self._alerts: list[AlertEvent] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        *,
        max_alerts: Optional[int] = None,
        max_seconds: Optional[float] = None,
        max_txs: Optional[int] = None,
    ) -> MonitorReport:
        """
        Drive the loop until one of the caps is hit.

        Either ``max_alerts``, ``max_seconds``, or ``max_txs`` must be
        provided so the loop is bounded. None of the three present →
        runs forever; callers must call ``stop()`` externally.
        """
        self._started_at = time.time()
        self._alerts = []
        seen_txs = 0

        try:
            for raw in self.subscriber.iter_transactions():
                if max_seconds and time.time() - self._started_at >= max_seconds:
                    break
                if max_txs is not None and seen_txs >= max_txs:
                    break

                seen_txs += 1
                self.dashboard.record_tx_observed()
                tx = self.classifier.classify(raw)
                if tx is None:
                    continue
                self.dashboard.record_tx_classified()

                matches = self.matcher.match(tx)
                if not matches:
                    continue
                self.dashboard.record_match(matches[0].signature_name)

                alert = self._build_alert(tx, matches[0])
                summary = self.dispatcher.dispatch(alert)
                self.dashboard.record_alert(alert)
                self._alerts.append(alert)
                if self.on_alert:
                    try:
                        self.on_alert(alert, summary)
                    except Exception:
                        logger.exception("on_alert callback raised")

                if max_alerts is not None and len(self._alerts) >= max_alerts:
                    break
        except MempoolError as exc:
            logger.warning("monitor stopped due to mempool error: %s", exc)
        finally:
            self.subscriber.stop()

        return self._build_report()

    def stop(self) -> None:
        self.subscriber.stop()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _default_subscriber(
        self, rpc_url: Optional[str], chain_id: int,
    ) -> BaseSubscriber:
        return JsonRpcPollingSubscriber(rpc_url=rpc_url, chain_id=chain_id)

    def _build_alert(
        self, tx: MempoolTx, match: SignatureMatch,
    ) -> AlertEvent:
        sig = next((s for s in self.signatures if s.id == match.signature_id), None)
        severity = _resolve_severity(sig, match) if sig else AlertSeverity.MEDIUM
        attack_class = sig.attack_class if sig else "unknown"
        protocol_name = sig.protocol_name if sig else None
        loss = sig.historical_loss_usd if sig else 0

        title = self._build_title(sig, match, severity)
        summary_line = self._build_summary(tx, sig, match)
        explorer_url = self._explorer_url(tx)

        return AlertEvent(
            severity=severity,
            title=title,
            summary=summary_line,
            description=summary_line,
            tx=tx,
            match=match,
            attack_class=attack_class,
            protocol_name=protocol_name,
            estimated_loss_usd=loss,
            dedup_key=f"{sig.id if sig else 'unknown'}::{tx.tx_hash}",
            explorer_url=explorer_url,
        )

    @staticmethod
    def _build_title(
        sig: Optional[PatternSignature],
        match: SignatureMatch,
        severity: AlertSeverity,
    ) -> str:
        name = sig.name if sig else match.signature_name
        return f"[{severity.value.upper()}] {name} (score {match.score:.2f})"

    @staticmethod
    def _build_summary(
        tx: MempoolTx,
        sig: Optional[PatternSignature],
        match: SignatureMatch,
    ) -> str:
        parts = []
        if sig and sig.protocol_name:
            parts.append(f"Protocol: {sig.protocol_name}")
        parts.append(f"Selector: `{tx.function_selector or '—'}`")
        parts.append(f"From: `{tx.from_address}`")
        if tx.to_address:
            parts.append(f"To: `{tx.to_address}`")
        if tx.value_wei:
            parts.append(f"Value: {tx.value_wei / 10**18:.4f} ETH")
        parts.append(f"Matched dimensions: {', '.join(d.value for d in match.matched_dimensions) or 'none'}")
        return " · ".join(parts)

    def _explorer_url(self, tx: MempoolTx) -> Optional[str]:
        prefix = _EXPLORER_PREFIX.get(tx.chain_id or self.chain_id)
        if not prefix or not tx.tx_hash:
            return None
        return prefix + tx.tx_hash

    def _build_report(self) -> MonitorReport:
        started_at = self._started_at or time.time()
        ended_at = time.time()
        return MonitorReport(
            started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at)),
            ended_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ended_at)),
            duration_seconds=round(ended_at - started_at, 3),
            alerts=list(self._alerts),
            health=self.dashboard.snapshot(),
            analysis_metadata={
                "signatures_loaded": len(self.signatures),
                "chain_id": self.chain_id,
                "subscriber": type(self.subscriber).__name__,
                "dispatcher_sinks": [type(s).__name__ for s in self.dispatcher.sinks],
            },
        )
