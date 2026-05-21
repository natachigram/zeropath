"""
ProtocolHealthDashboard — Phase 10.

Lightweight stats aggregator + optional stdlib HTTP server so a protocol
team can plug a Grafana/Prometheus or browser tab into the monitor without
shipping a heavy web framework.

Two surfaces:

  * :meth:`snapshot` — returns a :class:`HealthSnapshot`. The orchestrator
    calls this on demand or on a fixed cadence.
  * :meth:`serve` — boots a tiny ``http.server`` that returns the snapshot
    as JSON at ``/health`` and a minimal HTML view at ``/``. Designed for
    local dev / internal dashboards; production users typically scrape
    snapshot() into their own metrics pipeline.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

from zeropath.monitor.models import AlertEvent, AlertSeverity, HealthSnapshot

logger = logging.getLogger(__name__)


class ProtocolHealthDashboard:
    """Thread-safe in-process metrics + optional HTTP exposition."""

    def __init__(self, *, recent_alerts_size: int = 100) -> None:
        self._lock = threading.Lock()
        self._started_at = time.time()
        self._txs_observed = 0
        self._txs_classified = 0
        self._matches_found = 0
        self._alerts_dispatched = 0
        self._alerts_by_severity: Counter = Counter()
        self._alerts_by_attack_class: Counter = Counter()
        self._signature_hits: Counter = Counter()
        self._recent_alerts: deque[AlertEvent] = deque(maxlen=recent_alerts_size)
        self._last_alert_at: Optional[str] = None

        # HTTP plumbing
        self._http_server: Optional[HTTPServer] = None
        self._http_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Recording hooks (called by RealTimeMonitor)
    # ------------------------------------------------------------------

    def record_tx_observed(self) -> None:
        with self._lock:
            self._txs_observed += 1

    def record_tx_classified(self) -> None:
        with self._lock:
            self._txs_classified += 1

    def record_match(self, signature_name: str) -> None:
        with self._lock:
            self._matches_found += 1
            self._signature_hits[signature_name] += 1

    def record_alert(self, alert: AlertEvent) -> None:
        with self._lock:
            self._alerts_dispatched += 1
            self._alerts_by_severity[alert.severity.value] += 1
            self._alerts_by_attack_class[alert.attack_class] += 1
            self._recent_alerts.appendleft(alert)
            self._last_alert_at = alert.detected_at

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------

    def snapshot(self) -> HealthSnapshot:
        with self._lock:
            uptime = time.time() - self._started_at
            top = self._signature_hits.most_common(10)
            return HealthSnapshot(
                txs_observed=self._txs_observed,
                txs_classified=self._txs_classified,
                matches_found=self._matches_found,
                alerts_dispatched=self._alerts_dispatched,
                alerts_by_severity=dict(self._alerts_by_severity),
                alerts_by_attack_class=dict(self._alerts_by_attack_class),
                top_signatures=top,
                last_alert_at=self._last_alert_at,
                uptime_seconds=round(uptime, 1),
            )

    def recent_alerts(self) -> list[AlertEvent]:
        with self._lock:
            return list(self._recent_alerts)

    # ------------------------------------------------------------------
    # HTTP exposition (optional)
    # ------------------------------------------------------------------

    def serve(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 8765,
        block: bool = False,
    ) -> str:
        """
        Start a tiny ``http.server`` exposing /health (JSON) and / (HTML).

        Returns the bound URL. Non-blocking by default; pass ``block=True``
        to serve forever.
        """
        if self._http_server is not None:
            return f"http://{host}:{port}"

        dashboard = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # silence default stderr noise
                logger.debug("dashboard http: " + fmt, *args)

            def do_GET(self):
                if self.path.rstrip("/") in ("", "/"):
                    self._respond_html(dashboard._render_html())
                elif self.path.startswith("/health"):
                    self._respond_json(dashboard.snapshot().model_dump(mode="json"))
                elif self.path.startswith("/alerts"):
                    self._respond_json([
                        a.model_dump(mode="json") for a in dashboard.recent_alerts()
                    ])
                else:
                    self.send_response(404)
                    self.end_headers()

            def _respond_json(self, payload):
                body = json.dumps(payload, default=str).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _respond_html(self, html: str):
                body = html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._http_server = HTTPServer((host, port), _Handler)
        url = f"http://{host}:{port}"
        if block:
            try:
                self._http_server.serve_forever()
            finally:
                self.stop_serving()
        else:
            self._http_thread = threading.Thread(
                target=self._http_server.serve_forever,
                name="zeropath-dashboard-http",
                daemon=True,
            )
            self._http_thread.start()
        return url

    def stop_serving(self) -> None:
        if self._http_server is None:
            return
        try:
            self._http_server.shutdown()
            self._http_server.server_close()
        finally:
            self._http_server = None
            self._http_thread = None

    # ------------------------------------------------------------------
    # HTML render (minimal)
    # ------------------------------------------------------------------

    def _render_html(self) -> str:
        snap = self.snapshot()
        rows_sev = "".join(
            f"<tr><td>{k}</td><td>{v}</td></tr>"
            for k, v in snap.alerts_by_severity.items()
        ) or "<tr><td colspan='2'>none</td></tr>"
        rows_cls = "".join(
            f"<tr><td>{k}</td><td>{v}</td></tr>"
            for k, v in snap.alerts_by_attack_class.items()
        ) or "<tr><td colspan='2'>none</td></tr>"
        rows_top = "".join(
            f"<tr><td>{name}</td><td>{n}</td></tr>"
            for name, n in snap.top_signatures
        ) or "<tr><td colspan='2'>no matches yet</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><title>ZeroPath Monitor</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        margin: 2rem auto; max-width: 720px; color: #222; }}
h2 {{ margin-top: 1.5rem; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 1rem; }}
td, th {{ border: 1px solid #ddd; padding: 6px 12px; text-align: left; }}
.metric {{ font-size: 1.1em; }}
</style></head><body>
<h1>ZeroPath Real-Time Monitor</h1>
<p class="metric"><b>Uptime:</b> {snap.uptime_seconds:.0f}s
&middot; <b>Txs observed:</b> {snap.txs_observed:,}
&middot; <b>Classified:</b> {snap.txs_classified:,}
&middot; <b>Matches:</b> {snap.matches_found:,}
&middot; <b>Alerts:</b> {snap.alerts_dispatched:,}</p>
<h2>Alerts by severity</h2>
<table><tr><th>Severity</th><th>Count</th></tr>{rows_sev}</table>
<h2>Alerts by attack class</h2>
<table><tr><th>Attack class</th><th>Count</th></tr>{rows_cls}</table>
<h2>Top signatures hit</h2>
<table><tr><th>Signature</th><th>Hits</th></tr>{rows_top}</table>
<p class="metric"><a href="/health">/health</a> · <a href="/alerts">/alerts</a></p>
</body></html>"""
