"""
Contest corpus ingestion test suite — Phase 13 (verified sources).

Coverage matches the rewritten scrapers:
  - Code4rena: GitHub org repo enumeration + per-contest report.md
  - Sherlock: sherlock-audit org judging-repo enumeration + README.md
  - Cantina: portfolio metadata extraction (UUID + label only)
  - Solodit: API key auth + POST body + dump fallback
  - Spearbit: GitHub Contents API + filename pattern parse
  - ContestCorpusIngestor dispatch + KG insert + seed_all
  - Helpers: HTML strip, function-ref extraction, root-cause extraction

All tests run without touching the network — fetches are monkey-patched
and content is fed from in-memory fixtures.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from zeropath.knowledge import (
    CantinaScraper,
    Code4renaScraper,
    ContestCorpusIngestor,
    InMemoryKGStore,
    IngestReport,
    IngestionEngine,
    IntelSource,
    KnowledgeGraphOrchestrator,
    ScrapeStats,
    SherlockScraper,
    SoloditScraper,
    SpearbitScraper,
    default_cache_root,
    finding_fingerprint,
)
from zeropath.knowledge.contest_corpus import (
    _extract_function_refs,
    _protocol_from_c4r_repo,
    _protocol_from_sherlock_repo,
    _strip_html,
    _summarise_root_cause,
)
from zeropath.knowledge.schema import NodeLabel


# ===========================================================================
# Helpers
# ===========================================================================


def _mk_ingestor(tmp_path: Path) -> tuple[ContestCorpusIngestor, InMemoryKGStore]:
    store = InMemoryKGStore()
    KnowledgeGraphOrchestrator(store)
    engine = IngestionEngine(store, only_actionable=False)
    return ContestCorpusIngestor(engine, cache_root=tmp_path / "cache"), store


def _disable_refresh(monkeypatch) -> None:
    """Patch every scraper's _refresh_cache so tests stay offline."""
    for cls in (Code4renaScraper, SherlockScraper, CantinaScraper,
                SoloditScraper, SpearbitScraper):
        monkeypatch.setattr(cls, "_refresh_cache", lambda self: None)


# ===========================================================================
# Fingerprint
# ===========================================================================


class TestFingerprint:
    def test_stable_for_identical_inputs(self):
        a = finding_fingerprint("code4rena", "aave-v3", "Reentrancy")
        b = finding_fingerprint("code4rena", "aave-v3", "Reentrancy")
        assert a == b

    def test_case_insensitive_title(self):
        a = finding_fingerprint("code4rena", "aave-v3", "Reentrancy")
        b = finding_fingerprint("code4rena", "aave-v3", "REENTRANCY")
        assert a == b

    def test_differs_on_source(self):
        a = finding_fingerprint("code4rena", "x", "y")
        b = finding_fingerprint("sherlock",  "x", "y")
        assert a != b


# ===========================================================================
# Helpers — HTML strip / function refs / repo-name parse / root cause
# ===========================================================================


class TestHtmlStripper:
    def test_basic(self):
        assert _strip_html("<p>Hello <b>world</b></p>") == "Hello world"

    def test_entities(self):
        assert _strip_html("a &lt; b") == "a < b"
        assert _strip_html("a &amp; b") == "a & b"


class TestExtractFunctionRefs:
    def test_finds_function_calls(self):
        refs = _extract_function_refs("calls withdraw() then transferFrom()")
        assert "withdraw" in refs and "transferFrom" in refs

    def test_filters_reserved(self):
        refs = _extract_function_refs("if (require(x)) { return foo(); }")
        assert "foo" in refs
        assert "if" not in refs and "require" not in refs and "return" not in refs

    def test_dedupes(self):
        refs = _extract_function_refs("a() a() a()")
        assert refs == ["a"]


class TestProtocolFromRepoName:
    def test_c4r_strips_date_and_findings(self):
        assert _protocol_from_c4r_repo("2024-02-tapioca-findings") == "tapioca"
        assert _protocol_from_c4r_repo("2023-10-nextgen-findings") == "nextgen"

    def test_c4r_falls_back_to_raw(self):
        assert _protocol_from_c4r_repo("not-a-c4r-repo") == "not-a-c4r-repo"

    def test_sherlock_strips_judging(self):
        assert _protocol_from_sherlock_repo("2025-07-cap-judging") == "cap"
        assert _protocol_from_sherlock_repo("2026-01-fluid-dex-v2-judging") == "fluid-dex-v2"


class TestRootCauseExtractor:
    def test_picks_named_section(self):
        body = (
            "Some intro.\n\n"
            "### Vulnerability Detail\n"
            "External call before state update.\n\n"
            "### Recommendation\nUse CEI.\n"
        )
        assert "external call" in _summarise_root_cause(body).lower()

    def test_falls_back_to_first_paragraph(self):
        body = "First paragraph describes bug.\n\nSecond paragraph."
        assert "First paragraph" in _summarise_root_cause(body)

    def test_empty(self):
        assert _summarise_root_cause("") == ""


# ===========================================================================
# Code4rena parsing — uses real report.md format
# ===========================================================================


_C4R_REPORT_SAMPLE = """\
# 2024-02-tapioca Findings & Analysis Report

The C4 analysis yielded an aggregated total of 14 unique vulnerabilities.

## [H-01] Reentrancy in withdraw() drains the vault

### Description
The withdraw() function makes an external call before updating state.

### Recommendation
Apply CEI ordering.

## [M-02] Missing slippage check in swap()

### Description
swap() ignores the caller-supplied amountOutMin.

## [QA-01] Inconsistent error messages

Minor naming inconsistencies.
"""


class TestCode4renaParsing:
    def test_parses_three_findings_from_real_format(self, tmp_path):
        scraper = Code4renaScraper(cache_root=tmp_path)
        out = list(scraper._iter_findings(
            _C4R_REPORT_SAMPLE,
            contest_id="2024-02-tapioca-findings",
        ))
        codes = sorted(r.raw_payload["severity_code"] for r in out)
        assert codes == ["H", "M", "QA"]

    def test_protocol_field_stripped_from_repo_name(self, tmp_path):
        scraper = Code4renaScraper(cache_root=tmp_path)
        out = list(scraper._iter_findings(
            _C4R_REPORT_SAMPLE, contest_id="2024-02-tapioca-findings",
        ))
        assert all(r.protocol == "tapioca" for r in out)

    def test_source_url_built(self, tmp_path):
        scraper = Code4renaScraper(cache_root=tmp_path)
        out = list(scraper._iter_findings(
            _C4R_REPORT_SAMPLE, contest_id="2024-02-tapioca-findings",
        ))
        assert "code-423n4" in out[0].source_url
        assert "2024-02-tapioca-findings" in out[0].source_url
        assert "report.md" in out[0].source_url

    def test_attack_class_inferred(self, tmp_path):
        scraper = Code4renaScraper(cache_root=tmp_path)
        out = list(scraper._iter_findings(
            _C4R_REPORT_SAMPLE, contest_id="2024-02-x-findings",
        ))
        assert out[0].attack_class == "reentrancy"

    def test_tags_contain_contest_metadata(self, tmp_path):
        scraper = Code4renaScraper(cache_root=tmp_path)
        out = list(scraper._iter_findings(
            _C4R_REPORT_SAMPLE, contest_id="2024-02-tapioca-findings",
        ))
        tags = out[0].tags
        assert "contest:code4rena" in tags
        assert any(t.startswith("severity:H") for t in tags)
        assert any("contest_id:2024-02-tapioca-findings" in t for t in tags)


class TestCode4renaScrapeFlow:
    def test_scrape_walks_cached_inputs(self, tmp_path, monkeypatch):
        cache_root = tmp_path / "code4rena"
        cache_root.mkdir(parents=True)
        (cache_root / "2024-02-tapioca-findings.md").write_text(_C4R_REPORT_SAMPLE)
        monkeypatch.setattr(Code4renaScraper, "_refresh_cache", lambda self: None)
        scraper = Code4renaScraper(cache_root=tmp_path)
        records, stats = scraper.scrape()
        assert stats.accepted == 3
        assert len(records) == 3

    def test_max_findings_caps(self, tmp_path, monkeypatch):
        cache_root = tmp_path / "code4rena"
        cache_root.mkdir(parents=True)
        (cache_root / "2024-02-x-findings.md").write_text(_C4R_REPORT_SAMPLE)
        monkeypatch.setattr(Code4renaScraper, "_refresh_cache", lambda self: None)
        scraper = Code4renaScraper(cache_root=tmp_path, max_findings=1)
        records, _ = scraper.scrape()
        assert len(records) == 1


# ===========================================================================
# Sherlock parsing — matches sherlock-audit judging README format
# ===========================================================================


_SHERLOCK_README_SAMPLE = """\
# Cap Issue Reports

## Issue H-1: Oracle freshness not checked

### Summary
The pool reads Chainlink prices without validating updatedAt.

### Root Cause
latestAnswer() bypasses the heartbeat freshness check.

### Recommendation
Use latestRoundData() and assert updatedAt + heartbeat > block.timestamp.

## Issue M-1: Reentrancy on claimRewards()

### Summary
claimRewards() sends tokens before zeroing pending[user].

## Issue I-1: Event missing for setOracle()

Minor: emit OracleChanged for indexers.
"""


class TestSherlockParsing:
    def _seed(self, tmp_path) -> Path:
        cache_root = tmp_path / "sherlock"
        cache_root.mkdir(parents=True)
        (cache_root / "2025-07-cap-judging.md").write_text(_SHERLOCK_README_SAMPLE)
        return tmp_path

    def test_parses_three_findings(self, tmp_path, monkeypatch):
        self._seed(tmp_path)
        monkeypatch.setattr(SherlockScraper, "_refresh_cache", lambda self: None)
        scraper = SherlockScraper(cache_root=tmp_path)
        records, _ = scraper.scrape()
        assert len(records) == 3

    def test_severity_codes(self, tmp_path, monkeypatch):
        self._seed(tmp_path)
        monkeypatch.setattr(SherlockScraper, "_refresh_cache", lambda self: None)
        scraper = SherlockScraper(cache_root=tmp_path)
        records, _ = scraper.scrape()
        codes = sorted(r.raw_payload["severity_code"] for r in records)
        assert codes == ["H", "I", "M"]

    def test_protocol_extracted(self, tmp_path, monkeypatch):
        self._seed(tmp_path)
        monkeypatch.setattr(SherlockScraper, "_refresh_cache", lambda self: None)
        scraper = SherlockScraper(cache_root=tmp_path)
        records, _ = scraper.scrape()
        assert all(r.protocol == "cap" for r in records)

    def test_source_url_points_to_judging_repo(self, tmp_path, monkeypatch):
        self._seed(tmp_path)
        monkeypatch.setattr(SherlockScraper, "_refresh_cache", lambda self: None)
        scraper = SherlockScraper(cache_root=tmp_path)
        records, _ = scraper.scrape()
        for r in records:
            assert "sherlock-audit" in r.source_url
            assert "2025-07-cap-judging" in r.source_url


# ===========================================================================
# Cantina — metadata-only from portfolio listings
# ===========================================================================


_CANTINA_SITEMAP_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://cantina.xyz/portfolio/5900a399-ec2e-4e3c-aa9f-54b0a110b5c5</loc></url>
  <url><loc>https://cantina.xyz/portfolio/5035772b-2800-4f00-bb62-e7994419f8dd</loc></url>
  <url><loc>https://cantina.xyz/portfolio/c9f7110b-c112-4568-871f-9852ffbe1251</loc></url>
  <!-- Duplicate UUID should be dedupped -->
  <url><loc>https://cantina.xyz/portfolio/5900a399-ec2e-4e3c-aa9f-54b0a110b5c5</loc></url>
  <!-- Non-portfolio URL — should be ignored -->
  <url><loc>https://cantina.xyz/competitions</loc></url>
</urlset>
"""


class TestCantinaParsing:
    def test_extracts_unique_uuids_from_sitemap(self, tmp_path, monkeypatch):
        cache = tmp_path / "cantina"
        cache.mkdir(parents=True)
        (cache / "abc.xml").write_text(_CANTINA_SITEMAP_XML)
        monkeypatch.setattr(CantinaScraper, "_refresh_cache", lambda self: None)
        scraper = CantinaScraper(cache_root=tmp_path)
        records, _ = scraper.scrape()
        assert len(records) == 3
        uuids = {r.raw_payload["uuid"] for r in records}
        assert "5900a399-ec2e-4e3c-aa9f-54b0a110b5c5" in uuids
        assert "5035772b-2800-4f00-bb62-e7994419f8dd" in uuids

    def test_source_url_built_per_uuid(self, tmp_path, monkeypatch):
        cache = tmp_path / "cantina"
        cache.mkdir(parents=True)
        (cache / "abc.xml").write_text(_CANTINA_SITEMAP_XML)
        monkeypatch.setattr(CantinaScraper, "_refresh_cache", lambda self: None)
        scraper = CantinaScraper(cache_root=tmp_path)
        records, _ = scraper.scrape()
        for r in records:
            assert r.source_url.startswith("https://cantina.xyz/portfolio/")
            assert "metadata_only" in r.tags
            assert "contest:cantina" in r.tags

    def test_non_portfolio_urls_ignored(self, tmp_path, monkeypatch):
        cache = tmp_path / "cantina"
        cache.mkdir(parents=True)
        (cache / "x.xml").write_text(_CANTINA_SITEMAP_XML)
        monkeypatch.setattr(CantinaScraper, "_refresh_cache", lambda self: None)
        scraper = CantinaScraper(cache_root=tmp_path)
        records, _ = scraper.scrape()
        for r in records:
            assert "/competitions" not in r.source_url

    def test_extra_urls_appended(self, tmp_path):
        scraper = CantinaScraper(
            cache_root=tmp_path,
            extra_report_urls=["https://example.com/extra"],
        )
        assert "https://example.com/extra" in scraper.extra_urls


# ===========================================================================
# Solodit — POST with API key, dump fallback
# ===========================================================================


_SOLODIT_DUMP = [
    {
        "title": "Reentrancy in deposit",
        "protocol_category": "ExampleDAO",
        "audit_firm": "code4rena",
        "severity": "high",
        "tags": ["reentrancy", "callback"],
        "url": "https://code4rena.com/issue/123",
        "description": "External call before balance update.",
    },
    {
        "title": "Oracle manipulation",
        "protocol": "MoneyMarket",
        "source": "sherlock",
        "severity": "critical",
        "category": "Single-block spot price",
        "slug": "abc-123",
        "description": "Uses getReserves() for liquidation prices.",
    },
    {"no_title": True},   # malformed → skipped
]


class TestSoloditParsing:
    def test_parses_dump(self, tmp_path):
        dump = tmp_path / "dump.json"
        dump.write_text(json.dumps(_SOLODIT_DUMP))
        scraper = SoloditScraper(cache_root=tmp_path, dump_path=dump)
        records, stats = scraper.scrape()
        assert len(records) == 2
        assert stats.accepted == 2

    def test_severity_in_tags(self, tmp_path):
        dump = tmp_path / "d.json"
        dump.write_text(json.dumps(_SOLODIT_DUMP))
        scraper = SoloditScraper(cache_root=tmp_path, dump_path=dump)
        records, _ = scraper.scrape()
        assert any("severity:H" in t for r in records for t in r.tags)

    def test_upstream_source_preserved(self, tmp_path):
        dump = tmp_path / "d.json"
        dump.write_text(json.dumps(_SOLODIT_DUMP))
        scraper = SoloditScraper(cache_root=tmp_path, dump_path=dump)
        records, _ = scraper.scrape()
        tags_joined = " ".join(t for r in records for t in r.tags)
        assert "upstream:code4rena" in tags_joined
        assert "upstream:sherlock" in tags_joined

    def test_slug_becomes_url_when_no_url(self, tmp_path):
        dump = tmp_path / "d.json"
        dump.write_text(json.dumps([{
            "title": "X", "slug": "my-slug", "severity": "high",
        }]))
        scraper = SoloditScraper(cache_root=tmp_path, dump_path=dump)
        records, _ = scraper.scrape()
        assert records[0].source_url == "https://solodit.cyfrin.io/issues/my-slug"

    def test_no_key_and_no_dump_yields_zero(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SOLODIT_API_KEY", raising=False)
        monkeypatch.delenv("CYFRIN_API_KEY", raising=False)
        scraper = SoloditScraper(cache_root=tmp_path)
        records, _ = scraper.scrape()
        assert records == []

    def test_api_key_picked_from_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SOLODIT_API_KEY", "secret-xyz")
        scraper = SoloditScraper(cache_root=tmp_path)
        assert scraper.api_key == "secret-xyz"


# ===========================================================================
# Spearbit — GitHub Contents API + PDF filename parse
# ===========================================================================


_SPEARBIT_INDEX_RESPONSE = [
    {
        "name": "Buck-Labs-Spearbit-Security-Review-January-2026.pdf",
        "html_url": "https://github.com/spearbit/portfolio/blob/main/pdfs/Buck-Labs-Spearbit-Security-Review-January-2026.pdf",
        "download_url": "https://raw.githubusercontent.com/spearbit/portfolio/main/pdfs/Buck-Labs-Spearbit-Security-Review-January-2026.pdf",
    },
    {
        "name": "Morpho-Spearbit-Security-Review-September-2025.pdf",
        "html_url": "https://github.com/spearbit/portfolio/blob/main/pdfs/Morpho-Spearbit-Security-Review-September-2025.pdf",
    },
    {"name": "README.md", "html_url": "https://example.com/readme"},  # ignored
]


class TestSpearbitParsing:
    def test_extracts_each_pdf(self, tmp_path, monkeypatch):
        cache = tmp_path / "spearbit"
        cache.mkdir(parents=True)
        (cache / "index.json").write_text(json.dumps(_SPEARBIT_INDEX_RESPONSE))
        monkeypatch.setattr(SpearbitScraper, "_refresh_cache", lambda self: None)
        scraper = SpearbitScraper(cache_root=tmp_path)
        records, _ = scraper.scrape()
        protocols = sorted(r.protocol for r in records)
        assert "Buck Labs" in protocols
        assert "Morpho" in protocols

    def test_review_date_extracted(self, tmp_path, monkeypatch):
        cache = tmp_path / "spearbit"
        cache.mkdir(parents=True)
        (cache / "index.json").write_text(json.dumps(_SPEARBIT_INDEX_RESPONSE))
        monkeypatch.setattr(SpearbitScraper, "_refresh_cache", lambda self: None)
        scraper = SpearbitScraper(cache_root=tmp_path)
        records, _ = scraper.scrape()
        dates = {r.incident_date for r in records}
        assert "2026-01-01" in dates
        assert "2025-09-01" in dates

    def test_non_pdf_ignored(self, tmp_path, monkeypatch):
        cache = tmp_path / "spearbit"
        cache.mkdir(parents=True)
        (cache / "index.json").write_text(json.dumps(_SPEARBIT_INDEX_RESPONSE))
        monkeypatch.setattr(SpearbitScraper, "_refresh_cache", lambda self: None)
        scraper = SpearbitScraper(cache_root=tmp_path)
        records, _ = scraper.scrape()
        assert all(".pdf" not in r.protocol.lower() for r in records)

    def test_html_url_used_when_present(self, tmp_path, monkeypatch):
        cache = tmp_path / "spearbit"
        cache.mkdir(parents=True)
        (cache / "index.json").write_text(json.dumps(_SPEARBIT_INDEX_RESPONSE))
        monkeypatch.setattr(SpearbitScraper, "_refresh_cache", lambda self: None)
        scraper = SpearbitScraper(cache_root=tmp_path)
        records, _ = scraper.scrape()
        for r in records:
            assert "github.com/spearbit/portfolio" in r.source_url


# ===========================================================================
# Orchestrator
# ===========================================================================


class TestContestCorpusIngestor:
    def _seed_c4r(self, tmp_path) -> Path:
        cache_root = tmp_path / "cache"
        c4r_dir = cache_root / "code4rena"
        c4r_dir.mkdir(parents=True)
        (c4r_dir / "2024-02-tapioca-findings.md").write_text(_C4R_REPORT_SAMPLE)
        return cache_root

    def test_unknown_source_raises(self, tmp_path):
        ingestor, _ = _mk_ingestor(tmp_path)
        with pytest.raises(ValueError):
            ingestor.ingest(IntelSource.OTHER)

    def test_inserts_into_kg(self, tmp_path, monkeypatch):
        _disable_refresh(monkeypatch)
        cache_root = self._seed_c4r(tmp_path)
        ingestor, store = _mk_ingestor(tmp_path)
        ingestor.cache_root = cache_root
        summary = ingestor.ingest(IntelSource.CODE4RENA)
        assert summary["records_ingested"] >= 3
        incidents = store.find_by_label(NodeLabel.EXTERNAL_INCIDENT)
        assert len(incidents) >= 3

    def test_max_findings_propagated(self, tmp_path, monkeypatch):
        _disable_refresh(monkeypatch)
        cache_root = self._seed_c4r(tmp_path)
        ingestor, _ = _mk_ingestor(tmp_path)
        ingestor.cache_root = cache_root
        summary = ingestor.ingest(IntelSource.CODE4RENA, max_findings=1)
        assert summary["records_ingested"] == 1

    def test_seed_all_iterates_sources(self, tmp_path, monkeypatch):
        _disable_refresh(monkeypatch)
        ingestor, _ = _mk_ingestor(tmp_path)
        report = ingestor.seed_all(
            sources=[IntelSource.CODE4RENA, IntelSource.SHERLOCK],
            max_per_source=0,
        )
        assert "code4rena" in report.by_source
        assert "sherlock" in report.by_source


# ===========================================================================
# Default cache root + enum
# ===========================================================================


class TestDefaultCacheRoot:
    def test_returns_existing_dir(self):
        path = default_cache_root()
        assert path.exists() and path.is_dir()


class TestIntelSourceEnum:
    def test_contest_sources_present(self):
        for name in ("CODE4RENA", "SHERLOCK", "CANTINA", "SOLODIT", "SPEARBIT"):
            assert hasattr(IntelSource, name)


class TestScrapeStats:
    def test_defaults(self):
        s = ScrapeStats()
        assert s.accepted == 0
        assert s.skipped == 0
        assert s.errors == []
        assert s.fetched == 0


class TestIngestReportModel:
    def test_default_empty(self):
        r = IngestReport()
        assert r.total_records == 0
        assert r.total_errors == 0
        assert r.by_source == {}


# ===========================================================================
# GitHub helpers (mocked HTTP)
# ===========================================================================


class TestGithubHelpers:
    def test_list_org_repos_filters_by_pattern(self, tmp_path, monkeypatch):
        from zeropath.knowledge.contest_corpus import _list_org_repos
        import re as _re
        import requests as _r

        class FakeResp:
            def __init__(self, body, status_code=200):
                self._body = body
                self.status_code = status_code
                self.ok = 200 <= status_code < 300
                self.text = ""

            def json(self):
                return self._body

        pages = iter([
            [{"name": "2024-02-tapioca-findings"}, {"name": "random-repo"},
             {"name": "2024-03-fluid-findings"}],
            [],
        ])

        def fake_get(url, headers=None, params=None, timeout=None):
            return FakeResp(next(pages), 200)

        session = _r.Session()
        monkeypatch.setattr(session, "get", fake_get)
        repos = _list_org_repos(
            session, "code-423n4",
            name_pattern=_re.compile(r"-findings$"),
        )
        assert len(repos) == 2
        assert all(r["name"].endswith("-findings") for r in repos)

    def test_list_org_repos_handles_rate_limit(self, tmp_path, monkeypatch):
        from zeropath.knowledge.contest_corpus import _list_org_repos
        import re as _re
        import requests as _r

        class FakeResp:
            status_code = 403
            ok = False
            text = "API rate limit exceeded"

            def json(self):
                return {}

        session = _r.Session()
        monkeypatch.setattr(session, "get", lambda *a, **kw: FakeResp())
        repos = _list_org_repos(
            session, "code-423n4", name_pattern=_re.compile(r"-findings$"),
        )
        assert repos == []
