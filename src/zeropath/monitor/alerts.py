"""
Alert dispatcher + sinks — Phase 10.

Spec (phases.md, PHASE 10):
    "alert system (Discord, Slack, PagerDuty)"

Every sink follows the canonical payload shape for its destination
(verified against the 2025-2026 docs for Discord webhooks, Slack incoming
webhooks, and PagerDuty Events API v2). Webhook URLs / routing keys are
the only credentials needed — no SDK install.

The dispatcher fans the alert out to every configured sink, captures
per-sink outcomes, and never lets one broken channel drop the others.
"""

from __future__ import annotations

import json
import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

import requests

from zeropath.monitor.models import (
    AlertChannel,
    AlertEvent,
    AlertSeverity,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-sink result record
# ---------------------------------------------------------------------------


@dataclass
class DispatchResult:
    channel: AlertChannel
    ok: bool
    status_code: Optional[int] = None
    error: Optional[str] = None
    response_payload: Optional[dict] = None


@dataclass
class DispatchSummary:
    alert_id: str
    results: list[DispatchResult] = field(default_factory=list)

    @property
    def any_succeeded(self) -> bool:
        return any(r.ok for r in self.results)

    @property
    def all_succeeded(self) -> bool:
        return bool(self.results) and all(r.ok for r in self.results)


# ---------------------------------------------------------------------------
# Base sink
# ---------------------------------------------------------------------------


class BaseAlertSink(ABC):
    """Single channel target. Subclasses implement :meth:`send`."""

    channel: AlertChannel = AlertChannel.WEBHOOK

    def __init__(self, *, timeout: int = 10, dry_run: bool = False) -> None:
        self.timeout = timeout
        self.dry_run = dry_run
        self._session = requests.Session()

    @abstractmethod
    def send(self, alert: AlertEvent) -> DispatchResult: ...

    # ------------------------------------------------------------------

    def _http_post(self, url: str, payload: dict) -> DispatchResult:
        if self.dry_run:
            logger.info("[dry-run] %s payload: %s", self.channel.value, json.dumps(payload)[:300])
            return DispatchResult(channel=self.channel, ok=True, status_code=200,
                                   response_payload={"dry_run": True})
        try:
            resp = self._session.post(url, json=payload, timeout=self.timeout)
        except requests.RequestException as exc:
            return DispatchResult(channel=self.channel, ok=False, error=str(exc))
        ok = 200 <= resp.status_code < 300
        body: Optional[dict] = None
        try:
            body = resp.json() if resp.content else None
        except ValueError:
            body = None
        return DispatchResult(
            channel=self.channel, ok=ok, status_code=resp.status_code,
            response_payload=body,
            error=None if ok else f"HTTP {resp.status_code}: {resp.text[:200]}",
        )


# ---------------------------------------------------------------------------
# Discord
# ---------------------------------------------------------------------------


class DiscordSink(BaseAlertSink):
    """
    Discord webhook sink.

    Endpoint: ``POST https://discord.com/api/webhooks/{id}/{token}``
    No auth header; the URL is the secret.

    Payload follows the rich-embed schema documented at
    https://docs.discord.com/developers/resources/webhook with these caps:
      - content max 2000 chars
      - up to 10 embeds per message; total embed text cap 6000 chars
      - embed title 256, description 4096, field name 256, field value 1024

    Rate limit: ~5 requests / 2s per webhook (429 with `retry_after`).
    """

    channel = AlertChannel.DISCORD

    _MAX_TITLE = 256
    _MAX_DESCRIPTION = 4096
    _MAX_FIELD_VALUE = 1024

    def __init__(
        self,
        webhook_url: str,
        *,
        username: str = "ZeroPath",
        avatar_url: Optional[str] = None,
        mention_role_id: Optional[str] = None,
        timeout: int = 10,
        dry_run: bool = False,
    ) -> None:
        super().__init__(timeout=timeout, dry_run=dry_run)
        if not webhook_url or not webhook_url.startswith("https://"):
            raise ValueError("Discord webhook URL must be https://discord.com/api/webhooks/...")
        self.webhook_url = webhook_url
        self.username = username
        self.avatar_url = avatar_url
        self.mention_role_id = mention_role_id

    def send(self, alert: AlertEvent) -> DispatchResult:
        payload = self._build_payload(alert)
        return self._http_post(self.webhook_url, payload)

    # ------------------------------------------------------------------

    def _build_payload(self, alert: AlertEvent) -> dict:
        content = ""
        if self.mention_role_id and alert.severity in (
            AlertSeverity.CRITICAL, AlertSeverity.HIGH,
        ):
            content = f"<@&{self.mention_role_id}>"

        fields = [
            {"name": "Severity", "value": alert.severity.value.upper(), "inline": True},
            {"name": "Attack class", "value": alert.attack_class[:self._MAX_FIELD_VALUE], "inline": True},
            {"name": "Score", "value": f"{alert.match.score:.2f}", "inline": True},
            {"name": "Tx hash", "value": (alert.tx.tx_hash or "—")[:self._MAX_FIELD_VALUE], "inline": False},
        ]
        if alert.protocol_name:
            fields.append({"name": "Protocol", "value": alert.protocol_name, "inline": True})
        if alert.estimated_loss_usd:
            fields.append({
                "name": "Est. loss (USD)",
                "value": f"${alert.estimated_loss_usd:,}",
                "inline": True,
            })
        if alert.explorer_url:
            fields.append({"name": "Explorer", "value": alert.explorer_url, "inline": False})

        return {
            "username": self.username,
            **({"avatar_url": self.avatar_url} if self.avatar_url else {}),
            **({"content": content} if content else {}),
            "embeds": [{
                "title": alert.title[:self._MAX_TITLE],
                "description": alert.summary[:self._MAX_DESCRIPTION],
                "color": alert.severity.discord_color,
                "timestamp": alert.detected_at,
                "fields": fields,
                "footer": {"text": "ZeroPath Real-Time Monitor"},
            }],
        }


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------


class SlackSink(BaseAlertSink):
    """
    Slack incoming-webhook sink.

    Endpoint: ``POST https://hooks.slack.com/services/...``. URL is the
    secret. Use ``attachments[]`` so the severity-colored left bar shows
    up; the Block Kit lives inside.
    """

    channel = AlertChannel.SLACK

    def __init__(
        self,
        webhook_url: str,
        *,
        timeout: int = 10,
        dry_run: bool = False,
    ) -> None:
        super().__init__(timeout=timeout, dry_run=dry_run)
        if not webhook_url or not webhook_url.startswith("https://"):
            raise ValueError("Slack webhook URL must be https://hooks.slack.com/services/...")
        self.webhook_url = webhook_url

    def send(self, alert: AlertEvent) -> DispatchResult:
        payload = self._build_payload(alert)
        return self._http_post(self.webhook_url, payload)

    # ------------------------------------------------------------------

    def _build_payload(self, alert: AlertEvent) -> dict:
        fallback = f"{alert.severity.value.upper()}: {alert.title}"
        section = {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{alert.title}*\n{alert.summary}",
            },
            "fields": [
                {"type": "mrkdwn", "text": f"*Severity:*\n{alert.severity.value.upper()}"},
                {"type": "mrkdwn", "text": f"*Attack class:*\n{alert.attack_class}"},
                {"type": "mrkdwn", "text": f"*Score:*\n{alert.match.score:.2f}"},
                {"type": "mrkdwn", "text": f"*Tx:*\n`{alert.tx.tx_hash or '—'}`"},
            ],
        }
        if alert.protocol_name:
            section["fields"].append({
                "type": "mrkdwn",
                "text": f"*Protocol:*\n{alert.protocol_name}",
            })
        if alert.estimated_loss_usd:
            section["fields"].append({
                "type": "mrkdwn",
                "text": f"*Est. loss:*\n${alert.estimated_loss_usd:,}",
            })

        blocks: list[dict] = [section]
        if alert.explorer_url:
            blocks.append({
                "type": "actions",
                "elements": [{
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View on explorer"},
                    "url": alert.explorer_url,
                    "style": "primary",
                }],
            })

        return {
            "text": fallback,
            "attachments": [{
                "color": alert.severity.slack_color,
                "blocks": blocks,
            }],
        }


# ---------------------------------------------------------------------------
# PagerDuty
# ---------------------------------------------------------------------------


class PagerDutySink(BaseAlertSink):
    """
    PagerDuty Events API v2 sink.

    Endpoint: ``POST https://events.pagerduty.com/v2/enqueue``
    Auth: ``routing_key`` carried in the body. The routing key comes from
    a service's Events API v2 integration.

    Behaviour:
      * Repeating ``trigger`` events with the same ``dedup_key`` updates
        the open alert instead of creating duplicates.
      * Severity must be one of: critical, error, warning, info.
    """

    channel = AlertChannel.PAGERDUTY
    _ENDPOINT = "https://events.pagerduty.com/v2/enqueue"

    def __init__(
        self,
        routing_key: str,
        *,
        source: str = "zeropath-monitor",
        client: str = "ZeroPath",
        client_url: Optional[str] = None,
        timeout: int = 10,
        dry_run: bool = False,
    ) -> None:
        super().__init__(timeout=timeout, dry_run=dry_run)
        if not routing_key:
            raise ValueError("PagerDuty routing_key is required")
        self.routing_key = routing_key
        self.source = source
        self.client = client
        self.client_url = client_url

    def send(self, alert: AlertEvent) -> DispatchResult:
        payload = self._build_payload(alert)
        return self._http_post(self._ENDPOINT, payload)

    # ------------------------------------------------------------------

    def _build_payload(self, alert: AlertEvent) -> dict:
        payload: dict[str, Any] = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": alert.dedup_key or alert.id,
            "payload": {
                "summary": alert.title[:1024],
                "severity": alert.severity.pagerduty,
                "source": self.source,
                "timestamp": alert.detected_at,
                "component": alert.protocol_name or "unknown-protocol",
                "group": "smart-contracts",
                "class": alert.attack_class,
                "custom_details": {
                    "summary": alert.summary,
                    "description": alert.description,
                    "tx_hash": alert.tx.tx_hash,
                    "from": alert.tx.from_address,
                    "to": alert.tx.to_address or "",
                    "value_wei": alert.tx.value_wei,
                    "function_selector": alert.tx.function_selector or "",
                    "match_score": alert.match.score,
                    "match_components": alert.match.components,
                    "matched_dimensions": [d.value for d in alert.match.matched_dimensions],
                    "estimated_loss_usd": alert.estimated_loss_usd,
                    "explorer_url": alert.explorer_url or "",
                },
            },
            "client": self.client,
        }
        if self.client_url:
            payload["client_url"] = self.client_url
        return payload


# ---------------------------------------------------------------------------
# Generic webhook + stdout
# ---------------------------------------------------------------------------


class GenericWebhookSink(BaseAlertSink):
    """POST the AlertEvent as JSON to any URL. Useful for custom routing."""

    channel = AlertChannel.WEBHOOK

    def __init__(
        self,
        url: str,
        *,
        timeout: int = 10,
        dry_run: bool = False,
        headers: Optional[dict[str, str]] = None,
    ) -> None:
        super().__init__(timeout=timeout, dry_run=dry_run)
        self.url = url
        self.extra_headers = headers or {}

    def send(self, alert: AlertEvent) -> DispatchResult:
        if self.extra_headers:
            self._session.headers.update(self.extra_headers)
        return self._http_post(self.url, alert.model_dump(mode="json"))


class StdoutSink(BaseAlertSink):
    """Always-on dev sink — prints structured alerts to stdout / a logger."""

    channel = AlertChannel.STDOUT

    def __init__(self, *, log_fn=None) -> None:
        super().__init__()
        self.log_fn = log_fn or logger.warning

    def send(self, alert: AlertEvent) -> DispatchResult:
        self.log_fn(
            "[%s] %s | tx=%s class=%s score=%.2f",
            alert.severity.value.upper(),
            alert.title,
            alert.tx.tx_hash,
            alert.attack_class,
            alert.match.score,
        )
        return DispatchResult(channel=self.channel, ok=True, status_code=0)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


# Routing rules: any sink registered as None routes EVERY alert; otherwise
# only the named severities go through.
_DEFAULT_SEVERITY_ROUTING: dict[AlertChannel, tuple[AlertSeverity, ...]] = {
    AlertChannel.PAGERDUTY: (AlertSeverity.CRITICAL,),
    AlertChannel.SLACK: (AlertSeverity.CRITICAL, AlertSeverity.HIGH),
    AlertChannel.DISCORD: (
        AlertSeverity.CRITICAL, AlertSeverity.HIGH, AlertSeverity.MEDIUM,
    ),
    AlertChannel.STDOUT: tuple(AlertSeverity),
    AlertChannel.WEBHOOK: tuple(AlertSeverity),
}


class AlertDispatcher:
    """
    Fan out one :class:`AlertEvent` to every registered sink.

    Parameters
    ----------
    sinks : list[BaseAlertSink]
        Channels in dispatch order. Each is consulted via the routing
        table for the alert's severity.
    routing : dict | None
        Override the per-channel severity allowlist.
    rate_limit_per_minute : int
        Cap dispatches per channel per minute. ``0`` disables the limiter.
    """

    def __init__(
        self,
        sinks: Iterable[BaseAlertSink],
        *,
        routing: Optional[dict[AlertChannel, tuple[AlertSeverity, ...]]] = None,
        rate_limit_per_minute: int = 60,
    ) -> None:
        self.sinks = list(sinks)
        self.routing = routing or dict(_DEFAULT_SEVERITY_ROUTING)
        self.rate_limit_per_minute = rate_limit_per_minute
        self._sent_timestamps: dict[AlertChannel, list[float]] = {}

    def dispatch(self, alert: AlertEvent) -> DispatchSummary:
        summary = DispatchSummary(alert_id=alert.id)
        for sink in self.sinks:
            if not self._allowed(sink.channel, alert.severity):
                continue
            if self._rate_limited(sink.channel):
                summary.results.append(DispatchResult(
                    channel=sink.channel, ok=False,
                    error="rate-limited",
                ))
                continue
            result = sink.send(alert)
            summary.results.append(result)
            self._note_send(sink.channel)
        return summary

    # ------------------------------------------------------------------

    def _allowed(self, channel: AlertChannel, severity: AlertSeverity) -> bool:
        rules = self.routing.get(channel)
        if rules is None:
            return True
        return severity in rules

    def _rate_limited(self, channel: AlertChannel) -> bool:
        if self.rate_limit_per_minute <= 0:
            return False
        now = time.monotonic()
        bucket = self._sent_timestamps.setdefault(channel, [])
        # Drop entries older than 60s.
        self._sent_timestamps[channel] = [t for t in bucket if now - t < 60.0]
        return len(self._sent_timestamps[channel]) >= self.rate_limit_per_minute

    def _note_send(self, channel: AlertChannel) -> None:
        self._sent_timestamps.setdefault(channel, []).append(time.monotonic())


# ---------------------------------------------------------------------------
# Env-driven factory
# ---------------------------------------------------------------------------


def build_default_dispatcher(*, dry_run: bool = False) -> AlertDispatcher:
    """
    Construct a dispatcher from environment variables. Useful for the CLI.

    Recognised vars:
      * ZEROPATH_DISCORD_WEBHOOK_URL
      * ZEROPATH_SLACK_WEBHOOK_URL
      * ZEROPATH_PAGERDUTY_ROUTING_KEY
      * ZEROPATH_GENERIC_WEBHOOK_URL
    """
    sinks: list[BaseAlertSink] = [StdoutSink()]
    if url := os.environ.get("ZEROPATH_DISCORD_WEBHOOK_URL"):
        sinks.append(DiscordSink(url, dry_run=dry_run))
    if url := os.environ.get("ZEROPATH_SLACK_WEBHOOK_URL"):
        sinks.append(SlackSink(url, dry_run=dry_run))
    if key := os.environ.get("ZEROPATH_PAGERDUTY_ROUTING_KEY"):
        sinks.append(PagerDutySink(key, dry_run=dry_run))
    if url := os.environ.get("ZEROPATH_GENERIC_WEBHOOK_URL"):
        sinks.append(GenericWebhookSink(url, dry_run=dry_run))
    return AlertDispatcher(sinks)
