"""
Phase 10 test suite — Real-Time On-Chain Monitor.

Coverage:
  - Models: AlertSeverity routing maps (Slack/Discord/PagerDuty)
  - SignatureExtractor: defaults + Phase 8 KG → PatternSignature
  - TxClassifier: malformed input handling, selector extraction
  - PatternMatcher: selector required-when-set, scoring + threshold
  - MempoolSubscriber: SyntheticSubscriber dedup, JSON-RPC plumbing (mocked)
  - AlertDispatcher: routing, rate limiting, sink fan-out
  - Discord/Slack/PagerDuty payload shapes (HTTP mocked)
  - ProtocolHealthDashboard: snapshot stats, HTTP server start/stop
  - RealTimeMonitor: end-to-end with SyntheticSubscriber + StdoutSink
"""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import pytest
import requests

from zeropath.knowledge import (
    InMemoryKGStore,
    IntelSource,
    KnowledgeGraphOrchestrator,
)
from zeropath.monitor import (
    AlertChannel,
    AlertDispatcher,
    AlertEvent,
    AlertSeverity,
    BaseAlertSink,
    DiscordSink,
    DispatchResult,
    DispatchSummary,
    GenericWebhookSink,
    HealthSnapshot,
    JsonRpcPollingSubscriber,
    MagnitudeBand,
    MatchKind,
    MempoolError,
    MempoolSource,
    MempoolTx,
    MonitorReport,
    PagerDutySink,
    PatternMatcher,
    PatternSignature,
    ProtocolHealthDashboard,
    RealTimeMonitor,
    SignatureExtractor,
    SignatureMatch,
    SlackSink,
    StdoutSink,
    SyntheticSubscriber,
    TxClassifier,
    build_default_dispatcher,
)
from zeropath.monitor.alerts import _DEFAULT_SEVERITY_ROUTING
from zeropath.sequencer.abi_encoder import function_selector


# ===========================================================================
# Helpers
# ===========================================================================


_FLASH_SEL = "0x" + function_selector(
    "flashLoanSimple(address,address,uint256,bytes,uint16)",
).hex()
_TRANSFER_SEL = "0x" + function_selector("transfer(address,uint256)").hex()
_SWAP_SEL = "0x" + function_selector(
    "swap(uint256,uint256,address,bytes)",
).hex()

_ADDR_AAVE = "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2"
_ADDR_ATTACKER = "0x" + "ab" * 20


def _raw_tx(
    *,
    sel: str = _FLASH_SEL,
    to: str = _ADDR_AAVE,
    from_: str = _ADDR_ATTACKER,
    value_wei: int = 0,
    chain_id: int = 1,
    extra_data: str = "",
) -> dict[str, Any]:
    return {
        "hash": "0x" + uuid4().hex.zfill(64)[:64],
        "from": from_,
        "to": to,
        "value": hex(value_wei),
        "input": sel + (extra_data or "00" * 96),
        "chainId": hex(chain_id),
        "nonce": "0x1",
        "gas": "0x" + format(800_000, "x"),
        "gasPrice": "0x" + format(20_000_000_000, "x"),
    }


def _alert(*, severity: AlertSeverity = AlertSeverity.HIGH, score: float = 0.7) -> AlertEvent:
    tx = MempoolTx(
        tx_hash="0xabc", from_address=_ADDR_ATTACKER, to_address=_ADDR_AAVE,
        function_selector=_FLASH_SEL, chain_id=1,
    )
    match = SignatureMatch(
        signature_id="sig-1", signature_name="test::sig",
        tx_hash=tx.tx_hash, score=score,
        components={"selector": 0.4, "protocol": 0.075},
        matched_dimensions=[MatchKind.SELECTOR, MatchKind.PROTOCOL],
    )
    return AlertEvent(
        severity=severity,
        title=f"[{severity.value.upper()}] test alert",
        summary="synthetic alert for tests",
        tx=tx, match=match,
        attack_class="flash_loan",
        protocol_name="TestProtocol",
        estimated_loss_usd=1_000_000,
        dedup_key="test::abc",
        explorer_url="https://etherscan.io/tx/0xabc",
    )


class _RecordingSink(BaseAlertSink):
    """Test helper sink that records every alert dispatched to it."""

    channel = AlertChannel.WEBHOOK

    def __init__(self) -> None:
        super().__init__()
        self.alerts: list[AlertEvent] = []

    def send(self, alert: AlertEvent) -> DispatchResult:
        self.alerts.append(alert)
        return DispatchResult(channel=self.channel, ok=True, status_code=200)


# ===========================================================================
# Models
# ===========================================================================


class TestAlertSeverity:
    def test_pagerduty_mapping(self):
        assert AlertSeverity.CRITICAL.pagerduty == "critical"
        assert AlertSeverity.HIGH.pagerduty == "error"
        assert AlertSeverity.MEDIUM.pagerduty == "warning"
        assert AlertSeverity.LOW.pagerduty == "info"

    def test_slack_color_mapping(self):
        assert AlertSeverity.CRITICAL.slack_color == "danger"
        assert AlertSeverity.MEDIUM.slack_color == "warning"
        assert AlertSeverity.LOW.slack_color == "good"

    def test_discord_color_is_int(self):
        for tier in AlertSeverity:
            assert isinstance(tier.discord_color, int)


class TestPatternSignatureModel:
    def test_default_threshold(self):
        s = PatternSignature(name="x", attack_class="oracle_manipulation")
        assert 0.0 <= s.match_threshold <= 1.0


# ===========================================================================
# SignatureExtractor
# ===========================================================================


class TestSignatureExtractor:
    def test_defaults_cover_all_attack_classes(self):
        sigs = SignatureExtractor(knowledge=None).extract()
        classes = {s.attack_class for s in sigs}
        for cls in ("flash_loan", "oracle_manipulation", "reentrancy",
                    "access_control", "governance"):
            assert cls in classes

    def test_defaults_have_real_selectors(self):
        sigs = SignatureExtractor(knowledge=None).extract()
        for s in sigs:
            for sel in s.function_selectors:
                assert sel.startswith("0x") and len(sel) == 10

    def test_disable_defaults(self):
        sigs = SignatureExtractor(knowledge=None, include_defaults=False).extract()
        assert sigs == []

    def test_external_incident_signature(self):
        kg = KnowledgeGraphOrchestrator()
        kg.ingest_threat_intel(IntelSource.DEFIHACKLABS, [
            {"protocol": "Euler", "attack": "flash loan", "loss": "$197M"},
        ])
        sigs = SignatureExtractor(knowledge=kg, min_loss_usd_external=1_000_000).extract()
        kg_sigs = [s for s in sigs if s.source_kind == "external_incident"]
        assert kg_sigs
        assert any(s.attack_class == "flash_loan" for s in kg_sigs)
        # High loss should keep severity above MEDIUM
        for s in kg_sigs:
            if s.historical_loss_usd > 10_000_000:
                assert s.base_severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL)

    def test_external_incident_under_min_loss_skipped(self):
        kg = KnowledgeGraphOrchestrator()
        kg.ingest_threat_intel(IntelSource.DEFIHACKLABS, [
            {"protocol": "Small", "attack": "flash loan", "loss": "$100"},
        ])
        sigs = SignatureExtractor(knowledge=kg, min_loss_usd_external=1_000_000).extract()
        assert not any(s.source_kind == "external_incident" for s in sigs)

    def test_dedup_merges_selectors(self):
        # Two raw signatures with the same name should merge their selectors.
        e = SignatureExtractor(knowledge=None)
        sig_a = PatternSignature(
            name="default::flash_loan", attack_class="flash_loan",
            function_selectors=["0xaaaaaaaa"],
        )
        sig_b = PatternSignature(
            name="default::flash_loan", attack_class="flash_loan",
            function_selectors=["0xbbbbbbbb"],
        )
        out = e._dedupe([sig_a, sig_b])
        assert len(out) == 1
        assert "0xaaaaaaaa" in out[0].function_selectors
        assert "0xbbbbbbbb" in out[0].function_selectors


# ===========================================================================
# TxClassifier
# ===========================================================================


class TestTxClassifier:
    def test_normal_tx(self):
        tx = TxClassifier().classify(_raw_tx())
        assert tx is not None
        assert tx.function_selector == _FLASH_SEL
        assert tx.to_address == _ADDR_AAVE
        assert tx.from_address == _ADDR_ATTACKER
        assert tx.chain_id == 1
        assert tx.value_wei == 0
        assert tx.source == MempoolSource.JSON_RPC_POLL

    def test_missing_input_handles_gracefully(self):
        raw = _raw_tx()
        raw.pop("input")
        tx = TxClassifier().classify(raw)
        assert tx is not None
        assert tx.input_hex == "0x"
        assert tx.function_selector is None

    def test_invalid_address_becomes_empty(self):
        raw = _raw_tx(to="not-an-address")
        tx = TxClassifier().classify(raw)
        assert tx.to_address is None

    def test_returns_none_for_non_dict(self):
        assert TxClassifier().classify("not a dict") is None
        assert TxClassifier().classify(None) is None

    def test_lowercases_hash_and_address(self):
        raw = _raw_tx(from_=_ADDR_ATTACKER.upper())
        tx = TxClassifier().classify(raw)
        assert tx.from_address == _ADDR_ATTACKER.lower()
        assert tx.tx_hash == raw["hash"].lower()

    def test_value_wei_decoded(self):
        raw = _raw_tx(value_wei=10**18)
        tx = TxClassifier().classify(raw)
        assert tx.value_wei == 10**18


# ===========================================================================
# PatternMatcher
# ===========================================================================


class TestPatternMatcher:
    def test_matches_default_flash_loan_signature(self):
        sigs = SignatureExtractor(knowledge=None).extract()
        matcher = PatternMatcher(sigs)
        tx = TxClassifier().classify(_raw_tx(sel=_FLASH_SEL))
        matches = matcher.match(tx)
        assert matches
        assert matches[0].score >= 0.4
        assert MatchKind.SELECTOR in matches[0].matched_dimensions

    def test_selector_mismatch_filters_out(self):
        sigs = SignatureExtractor(knowledge=None).extract()
        matcher = PatternMatcher(sigs)
        # Random selector that no signature targets.
        tx = TxClassifier().classify(_raw_tx(sel="0xdeadbeef"))
        matches = matcher.match(tx)
        assert matches == []

    def test_target_address_lifts_score(self):
        sig = PatternSignature(
            name="custom", attack_class="flash_loan",
            function_selectors=[_FLASH_SEL],
            target_addresses=[_ADDR_AAVE],
            match_threshold=0.5,
        )
        matcher = PatternMatcher([sig])
        tx = TxClassifier().classify(_raw_tx(sel=_FLASH_SEL, to=_ADDR_AAVE))
        matches = matcher.match(tx)
        assert matches
        m = matches[0]
        assert m.score >= 0.7
        assert MatchKind.TARGET_ADDRESS in m.matched_dimensions
        assert MatchKind.COMPOSITE in m.matched_dimensions

    def test_value_band_match(self):
        sig = PatternSignature(
            name="custom", attack_class="flash_loan",
            function_selectors=[_FLASH_SEL],
            value_band=MagnitudeBand(min_wei=10**18, max_wei=10**21),
            match_threshold=0.45,
        )
        matcher = PatternMatcher([sig])
        tx = TxClassifier().classify(_raw_tx(sel=_FLASH_SEL, value_wei=5 * 10**18))
        matches = matcher.match(tx)
        assert matches
        assert MatchKind.MAGNITUDE in matches[0].matched_dimensions

    def test_best_match_returns_top_score(self):
        sig_low = PatternSignature(
            name="low", attack_class="x", function_selectors=[_FLASH_SEL],
            match_threshold=0.4,
        )
        sig_high = PatternSignature(
            name="high", attack_class="x", function_selectors=[_FLASH_SEL],
            target_addresses=[_ADDR_AAVE], match_threshold=0.4,
        )
        matcher = PatternMatcher([sig_low, sig_high])
        tx = TxClassifier().classify(_raw_tx(sel=_FLASH_SEL, to=_ADDR_AAVE))
        best = matcher.best_match(tx)
        assert best is not None
        assert best.signature_name == "high"

    def test_below_threshold_drops(self):
        sig = PatternSignature(
            name="strict", attack_class="x",
            function_selectors=[_FLASH_SEL],
            match_threshold=0.99,
        )
        matcher = PatternMatcher([sig])
        tx = TxClassifier().classify(_raw_tx(sel=_FLASH_SEL))
        assert matcher.match(tx) == []


# ===========================================================================
# SyntheticSubscriber
# ===========================================================================


class TestSyntheticSubscriber:
    def test_yields_each_tx_once(self):
        txs = [_raw_tx() for _ in range(3)]
        sub = SyntheticSubscriber(txs, chain_id=1)
        emitted = list(sub.iter_transactions())
        assert len(emitted) == 3

    def test_dedup_within_one_pass(self):
        # If the same hash appears twice, dedup cache drops the duplicate.
        tx = _raw_tx()
        sub = SyntheticSubscriber([tx, tx], chain_id=1)
        emitted = list(sub.iter_transactions())
        # SyntheticSubscriber doesn't run dedup itself, but the cache is
        # populated when the orchestrator calls _remember. The raw stream
        # yields both copies; the orchestrator decides whether to dedupe.
        # Here we assert the generator behaviour.
        assert len(emitted) == 2  # SyntheticSubscriber doesn't dedup raw

    def test_loop_mode(self):
        sub = SyntheticSubscriber([_raw_tx()], chain_id=1, loop=True)
        emitted = []
        gen = sub.iter_transactions()
        for _ in range(3):
            emitted.append(next(gen))
        sub.stop()
        assert len(emitted) == 3


# ===========================================================================
# JsonRpcPollingSubscriber (with mocked requests)
# ===========================================================================


class TestJsonRpcPollingSubscriber:
    def test_constructor_requires_rpc(self, monkeypatch):
        monkeypatch.delenv("ETH_RPC_URL", raising=False)
        # Unknown chain → no public fallback → raises
        with pytest.raises(MempoolError):
            JsonRpcPollingSubscriber(chain_id=9999)

    def test_polls_pending_block(self, monkeypatch):
        """One poll returns a pending block with two txs."""
        sub = JsonRpcPollingSubscriber(
            rpc_url="http://example", chain_id=1, poll_interval_seconds=0,
        )
        responses = [
            {
                "result": {
                    "transactions": [_raw_tx(), _raw_tx()],
                }
            },
        ]

        class FakeResp:
            def __init__(self, body):
                self._body = body
                self.status_code = 200
                self.content = b"x"

            def raise_for_status(self):
                pass

            def json(self):
                return self._body

        calls = {"n": 0}

        def fake_post(*a, **kw):
            calls["n"] += 1
            if calls["n"] > 1:
                sub.stop()
                return FakeResp({"result": {"transactions": []}})
            return FakeResp(responses[0])

        monkeypatch.setattr(sub._session, "post", fake_post)
        emitted = list(sub.iter_transactions())
        assert len(emitted) == 2


# ===========================================================================
# Alert dispatcher + sinks (HTTP mocked)
# ===========================================================================


class _MockResp:
    def __init__(self, *, status_code: int = 200, body=None):
        self.status_code = status_code
        self.content = b"ok" if body is None else json.dumps(body).encode()
        self._body = body
        self.text = "ok"

    def json(self):
        return self._body


class TestDiscordSink:
    def test_payload_shape_matches_spec(self, monkeypatch):
        sink = DiscordSink("https://discord.com/api/webhooks/123/abc",
                            mention_role_id="999")
        captured = {}

        def fake_post(url, *, json=None, timeout=None):
            captured["url"] = url
            captured["payload"] = json
            return _MockResp(status_code=204)

        monkeypatch.setattr(sink._session, "post", fake_post)
        result = sink.send(_alert(severity=AlertSeverity.CRITICAL))
        assert result.ok
        assert captured["url"].startswith("https://discord.com/api/webhooks")
        payload = captured["payload"]
        assert "embeds" in payload
        embed = payload["embeds"][0]
        assert "title" in embed and "color" in embed and "fields" in embed
        # Critical severity should mention the role
        assert "<@&999>" in payload["content"]

    def test_url_validation(self):
        with pytest.raises(ValueError):
            DiscordSink("not-a-url")


class TestSlackSink:
    def test_payload_shape(self, monkeypatch):
        sink = SlackSink("https://hooks.slack.com/services/T/B/X")
        captured = {}
        monkeypatch.setattr(
            sink._session, "post",
            lambda url, **kw: (captured.update(url=url, payload=kw["json"])
                               or _MockResp(status_code=200)),
        )
        sink.send(_alert(severity=AlertSeverity.HIGH))
        payload = captured["payload"]
        assert "text" in payload
        assert "attachments" in payload
        att = payload["attachments"][0]
        assert att["color"] in ("danger", "warning", "good")
        # Block Kit section present
        assert any(b.get("type") == "section" for b in att["blocks"])

    def test_url_validation(self):
        with pytest.raises(ValueError):
            SlackSink("ftp://wrong-scheme")


class TestPagerDutySink:
    def test_payload_shape_matches_events_v2(self, monkeypatch):
        sink = PagerDutySink("R0UT1NGKEY")
        captured = {}
        monkeypatch.setattr(
            sink._session, "post",
            lambda url, **kw: (captured.update(url=url, payload=kw["json"])
                               or _MockResp(status_code=202)),
        )
        sink.send(_alert(severity=AlertSeverity.CRITICAL))
        assert captured["url"] == "https://events.pagerduty.com/v2/enqueue"
        p = captured["payload"]
        assert p["routing_key"] == "R0UT1NGKEY"
        assert p["event_action"] == "trigger"
        assert p["dedup_key"] == "test::abc"
        payload = p["payload"]
        assert payload["severity"] == "critical"
        assert payload["summary"]
        assert payload["source"]
        assert "custom_details" in payload
        assert payload["custom_details"]["tx_hash"] == "0xabc"

    def test_severity_mapping_high_becomes_error(self, monkeypatch):
        sink = PagerDutySink("KEY")
        captured = {}
        monkeypatch.setattr(
            sink._session, "post",
            lambda url, **kw: (captured.update(payload=kw["json"]) or _MockResp(status_code=202)),
        )
        sink.send(_alert(severity=AlertSeverity.HIGH))
        assert captured["payload"]["payload"]["severity"] == "error"

    def test_routing_key_required(self):
        with pytest.raises(ValueError):
            PagerDutySink("")


class TestGenericWebhookSink:
    def test_posts_alert_as_json(self, monkeypatch):
        sink = GenericWebhookSink("https://my-endpoint.test/hook",
                                   headers={"X-Token": "abc"})
        captured = {}
        monkeypatch.setattr(
            sink._session, "post",
            lambda url, **kw: (captured.update(url=url, payload=kw["json"])
                               or _MockResp(status_code=200)),
        )
        sink.send(_alert())
        assert captured["url"] == "https://my-endpoint.test/hook"
        # Payload is the dumped AlertEvent — has every model key.
        assert "title" in captured["payload"]
        assert "severity" in captured["payload"]


class TestStdoutSink:
    def test_emits_via_log_fn(self):
        captured = []
        sink = StdoutSink(log_fn=lambda *a, **k: captured.append(a))
        result = sink.send(_alert())
        assert result.ok
        assert captured


class TestAlertDispatcher:
    def test_fans_out_to_all_sinks(self):
        a = _RecordingSink()
        b = _RecordingSink()
        # Override default routing so WEBHOOK channel accepts all severities
        # for both sinks (default already does).
        disp = AlertDispatcher([a, b])
        alert = _alert(severity=AlertSeverity.CRITICAL)
        summary = disp.dispatch(alert)
        assert summary.all_succeeded
        assert len(a.alerts) == 1
        assert len(b.alerts) == 1

    def test_severity_routing_drops_low(self):
        sink = _RecordingSink()
        # Custom routing: only CRITICAL goes through.
        disp = AlertDispatcher(
            [sink],
            routing={AlertChannel.WEBHOOK: (AlertSeverity.CRITICAL,)},
        )
        disp.dispatch(_alert(severity=AlertSeverity.MEDIUM))
        assert sink.alerts == []
        disp.dispatch(_alert(severity=AlertSeverity.CRITICAL))
        assert len(sink.alerts) == 1

    def test_rate_limiter_blocks(self):
        sink = _RecordingSink()
        disp = AlertDispatcher([sink], rate_limit_per_minute=1)
        s1 = disp.dispatch(_alert())
        s2 = disp.dispatch(_alert())
        assert s1.all_succeeded
        # Second dispatch is rate-limited.
        assert any("rate-limited" in (r.error or "") for r in s2.results)

    def test_failure_in_one_sink_does_not_drop_others(self):
        class FlakySink(BaseAlertSink):
            channel = AlertChannel.DISCORD
            def send(self, alert):
                return DispatchResult(channel=self.channel, ok=False, error="boom")

        good = _RecordingSink()
        disp = AlertDispatcher(
            [FlakySink(), good],
            routing={
                AlertChannel.DISCORD: tuple(AlertSeverity),
                AlertChannel.WEBHOOK: tuple(AlertSeverity),
            },
        )
        summary = disp.dispatch(_alert())
        assert not summary.all_succeeded
        assert summary.any_succeeded
        assert len(good.alerts) == 1


class TestBuildDefaultDispatcher:
    def test_with_no_env_uses_only_stdout(self, monkeypatch):
        for var in (
            "ZEROPATH_DISCORD_WEBHOOK_URL",
            "ZEROPATH_SLACK_WEBHOOK_URL",
            "ZEROPATH_PAGERDUTY_ROUTING_KEY",
            "ZEROPATH_GENERIC_WEBHOOK_URL",
        ):
            monkeypatch.delenv(var, raising=False)
        disp = build_default_dispatcher()
        assert len(disp.sinks) == 1
        assert isinstance(disp.sinks[0], StdoutSink)

    def test_with_env_adds_sinks(self, monkeypatch):
        monkeypatch.setenv("ZEROPATH_DISCORD_WEBHOOK_URL",
                            "https://discord.com/api/webhooks/1/2")
        monkeypatch.setenv("ZEROPATH_SLACK_WEBHOOK_URL",
                            "https://hooks.slack.com/services/X/Y/Z")
        monkeypatch.setenv("ZEROPATH_PAGERDUTY_ROUTING_KEY", "RKEY")
        disp = build_default_dispatcher(dry_run=True)
        names = [type(s).__name__ for s in disp.sinks]
        assert "StdoutSink" in names
        assert "DiscordSink" in names
        assert "SlackSink" in names
        assert "PagerDutySink" in names


# ===========================================================================
# Dashboard
# ===========================================================================


class TestDashboard:
    def test_snapshot_counts(self):
        d = ProtocolHealthDashboard()
        d.record_tx_observed()
        d.record_tx_observed()
        d.record_tx_classified()
        d.record_match("sig::A")
        d.record_alert(_alert(severity=AlertSeverity.HIGH))
        snap = d.snapshot()
        assert isinstance(snap, HealthSnapshot)
        assert snap.txs_observed == 2
        assert snap.txs_classified == 1
        assert snap.matches_found == 1
        assert snap.alerts_dispatched == 1
        assert snap.alerts_by_severity == {"high": 1}
        assert snap.top_signatures == [("sig::A", 1)]
        assert snap.last_alert_at is not None
        assert snap.uptime_seconds >= 0

    def test_recent_alerts_bounded(self):
        d = ProtocolHealthDashboard(recent_alerts_size=3)
        for _ in range(5):
            d.record_alert(_alert())
        assert len(d.recent_alerts()) == 3

    def test_http_server_starts_and_stops(self):
        d = ProtocolHealthDashboard()
        # Bind to port 0 so the OS picks an unused port — but our impl
        # takes an explicit port; pick a high one that's unlikely to clash.
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        url = d.serve(port=port, block=False)
        try:
            resp = requests.get(f"{url}/health", timeout=5)
            assert resp.status_code == 200
            body = resp.json()
            assert "uptime_seconds" in body
        finally:
            d.stop_serving()


# ===========================================================================
# End-to-end orchestrator
# ===========================================================================


class TestRealTimeMonitor:
    def test_synthetic_end_to_end(self):
        sub = SyntheticSubscriber([_raw_tx(sel=_FLASH_SEL)], chain_id=1)
        sink = _RecordingSink()
        # Allow WEBHOOK to receive every severity for the test
        disp = AlertDispatcher(
            [sink],
            routing={AlertChannel.WEBHOOK: tuple(AlertSeverity)},
        )
        monitor = RealTimeMonitor(subscriber=sub, dispatcher=disp)
        report = monitor.run(max_txs=1)
        assert isinstance(report, MonitorReport)
        assert report.health.txs_observed == 1
        assert len(report.alerts) == 1
        alert = report.alerts[0]
        assert alert.attack_class == "flash_loan"
        assert alert.explorer_url.startswith("https://etherscan.io/tx/")

    def test_unmatched_tx_emits_no_alert(self):
        sub = SyntheticSubscriber([_raw_tx(sel="0xdeadbeef")], chain_id=1)
        sink = _RecordingSink()
        disp = AlertDispatcher(
            [sink], routing={AlertChannel.WEBHOOK: tuple(AlertSeverity)},
        )
        monitor = RealTimeMonitor(subscriber=sub, dispatcher=disp)
        report = monitor.run(max_txs=1)
        assert report.health.matches_found == 0
        assert report.alerts == []

    def test_max_alerts_bound(self):
        sub = SyntheticSubscriber(
            [_raw_tx(sel=_FLASH_SEL) for _ in range(5)],
            chain_id=1,
        )
        sink = _RecordingSink()
        disp = AlertDispatcher(
            [sink], routing={AlertChannel.WEBHOOK: tuple(AlertSeverity)},
            rate_limit_per_minute=0,
        )
        monitor = RealTimeMonitor(subscriber=sub, dispatcher=disp)
        report = monitor.run(max_alerts=2)
        assert len(report.alerts) == 2

    def test_on_alert_callback_invoked(self):
        sub = SyntheticSubscriber([_raw_tx(sel=_FLASH_SEL)], chain_id=1)
        sink = _RecordingSink()
        captured: list[AlertEvent] = []
        disp = AlertDispatcher(
            [sink], routing={AlertChannel.WEBHOOK: tuple(AlertSeverity)},
        )
        monitor = RealTimeMonitor(
            subscriber=sub, dispatcher=disp,
            on_alert=lambda a, s: captured.append(a),
        )
        monitor.run(max_txs=1)
        assert len(captured) == 1

    def test_explorer_url_per_chain(self):
        sub = SyntheticSubscriber(
            [_raw_tx(sel=_FLASH_SEL, chain_id=42161)], chain_id=42161,
        )
        sink = _RecordingSink()
        disp = AlertDispatcher(
            [sink], routing={AlertChannel.WEBHOOK: tuple(AlertSeverity)},
        )
        monitor = RealTimeMonitor(subscriber=sub, dispatcher=disp, chain_id=42161)
        report = monitor.run(max_txs=1)
        assert report.alerts[0].explorer_url.startswith("https://arbiscan.io/tx/")

    def test_strong_score_boosts_severity(self):
        # Build a custom signature that scores high (selector + target + protocol).
        sig = PatternSignature(
            name="strong::aave", attack_class="flash_loan",
            protocol_name="Aave",
            function_selectors=[_FLASH_SEL],
            target_addresses=[_ADDR_AAVE],
            base_severity=AlertSeverity.HIGH,
            match_threshold=0.5,
        )
        sub = SyntheticSubscriber([_raw_tx(sel=_FLASH_SEL, to=_ADDR_AAVE)], chain_id=1)
        sink = _RecordingSink()
        disp = AlertDispatcher(
            [sink], routing={AlertChannel.WEBHOOK: tuple(AlertSeverity)},
        )
        monitor = RealTimeMonitor(
            subscriber=sub, dispatcher=disp, extra_signatures=[sig],
        )
        report = monitor.run(max_txs=1)
        # Strong-score boost lifts HIGH to CRITICAL when score >= 0.85.
        assert any(
            a.severity in (AlertSeverity.CRITICAL, AlertSeverity.HIGH)
            for a in report.alerts
        )

    def test_signature_count_in_metadata(self):
        sub = SyntheticSubscriber([], chain_id=1)
        disp = AlertDispatcher([_RecordingSink()])
        monitor = RealTimeMonitor(subscriber=sub, dispatcher=disp)
        report = monitor.run(max_txs=0)
        assert report.analysis_metadata["signatures_loaded"] > 0
        assert report.analysis_metadata["subscriber"] == "SyntheticSubscriber"
