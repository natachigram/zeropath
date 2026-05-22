"""
Contest corpus ingestion — Phase 13 (verified sources, May 2026).

Scrapes historical audit findings from five public sources, normalises
into :class:`ExternalIncidentRecord`, and bulk-ingests into the Phase 8
knowledge graph.

**Verified upstream sources (re-checked May 2026):**

  * **Code4rena** — `code-423n4` GitHub org. Each completed contest lives
    in its own repo named ``YYYY-MM-{project}-findings`` with a
    ``report.md`` containing aggregated findings (H-01, M-02, …).
    There is NO single aggregated repo; enumeration uses the GitHub
    Org Repos API.

  * **Sherlock** — `sherlock-audit` GitHub org. Judging repos follow
    ``YYYY-MM-{project}-judging`` and ship findings in ``README.md``
    (M-1, M-2, …). The legacy `sherlock-protocol/sherlock-reports` repo
    holds PDF "Final" reports that we don't parse here (would need
    PDF tooling).

  * **Cantina** — `cantina.xyz/portfolio/{uuid}`. Full reports are
    PDFs behind a download wall; we ingest *metadata* (protocol,
    reviewers, date) from the portfolio listing only. Solodit covers
    the contained findings.

  * **Solodit** — `solodit.cyfrin.io/api/v1/solodit/findings`. **Requires
    an API key** (``X-Cyfrin-API-Key`` header) and uses POST with a
    JSON body. 49 000+ aggregated findings across Code4rena, Cantina,
    Sherlock, Spearbit, etc. — the single best source if you have a key.
    Falls back to a user-supplied JSON dump when no key.

  * **Spearbit** — `github.com/spearbit/portfolio` `/pdfs/` directory.
    Reports are PDFs named ``{Project}-Spearbit-Security-Review-
    {Month}-{Year}.pdf``. We metadata-only ingest (project + date)
    without PDF parsing.

Design constraints unchanged from before:
  * No required credentials beyond Solodit (which is optional).
  * Local cache under ``~/.zeropath/cache/contest_corpus/<source>/``.
  * Idempotent inserts via fingerprint.
  * Graceful network failure — partial progress preserved.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

import requests

from zeropath.knowledge.ingestion import IngestionEngine
from zeropath.knowledge.models import ExternalIncidentRecord, IntelSource
from zeropath.knowledge.threat_intel import (
    ParseStats,
    _coerce_loss_usd,
    normalise_attack_class,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cache + fingerprint helpers
# ---------------------------------------------------------------------------


def default_cache_root() -> Path:
    """``~/.zeropath/cache/contest_corpus`` — created on first use."""
    root = Path.home() / ".zeropath" / "cache" / "contest_corpus"
    root.mkdir(parents=True, exist_ok=True)
    return root


def finding_fingerprint(
    source: str, contest_id: str, finding_title: str,
) -> str:
    """Stable hex fingerprint over (source, contest, title)."""
    payload = f"{source}::{contest_id}::{finding_title.lower().strip()}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:32]


# ---------------------------------------------------------------------------
# GitHub helpers (shared by Code4rena + Sherlock + Spearbit scrapers)
# ---------------------------------------------------------------------------


GITHUB_API_BASE = "https://api.github.com"


def _github_headers(token: Optional[str] = None) -> dict[str, str]:
    """
    Build GitHub API headers. With a token, rate limit is 5,000/hour;
    without, 60/hour (which is enough for ~1 page of org listing).
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ZeroPath/0.9 contest-corpus",
    }
    token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _list_org_repos(
    session: requests.Session,
    org: str,
    *,
    name_pattern: re.Pattern[str],
    token: Optional[str] = None,
    timeout: int = 30,
    max_pages: int = 50,
) -> list[dict]:
    """
    Page through an org's repos and return those whose name matches
    ``name_pattern``. ``max_pages * 100`` is the hard ceiling.
    """
    out: list[dict] = []
    headers = _github_headers(token)
    for page in range(1, max_pages + 1):
        url = f"{GITHUB_API_BASE}/orgs/{org}/repos"
        params = {"per_page": 100, "page": page, "sort": "created", "direction": "desc"}
        try:
            resp = session.get(url, headers=headers, params=params, timeout=timeout)
        except requests.RequestException as exc:
            logger.warning("github: org=%s page=%d transport error: %s", org, page, exc)
            return out
        if resp.status_code == 403 and "rate limit" in resp.text.lower():
            logger.warning("github: rate-limited on org=%s; set GITHUB_TOKEN for 5000/h", org)
            return out
        if not resp.ok:
            logger.warning("github: org=%s page=%d HTTP %s", org, page, resp.status_code)
            return out
        repos = resp.json()
        if not repos:
            return out
        for repo in repos:
            if name_pattern.search(repo.get("name", "")):
                out.append(repo)
        if len(repos) < 100:
            return out
    return out


def _fetch_raw_file(
    session: requests.Session,
    owner: str,
    repo: str,
    path: str,
    *,
    branch: str = "main",
    timeout: int = 20,
) -> Optional[str]:
    """
    Fetch a file from a GitHub repo via raw.githubusercontent.com (no API
    quota). Returns the text body or None on 404 / transport error.
    """
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    try:
        resp = session.get(url, timeout=timeout)
    except requests.RequestException as exc:
        logger.debug("raw fetch failed for %s/%s/%s: %s", owner, repo, path, exc)
        return None
    if resp.status_code == 404:
        return None
    if not resp.ok:
        return None
    return resp.text


# ---------------------------------------------------------------------------
# Base scraper
# ---------------------------------------------------------------------------


@dataclass
class ScrapeStats(ParseStats):
    fetched: int = 0
    cached_hit: int = 0


class BaseScraper(ABC):
    """Common scaffolding for every per-source scraper."""

    source: IntelSource = IntelSource.OTHER
    cache_subdir: str = "other"

    def __init__(
        self,
        *,
        cache_root: Optional[Path] = None,
        timeout: int = 30,
        max_findings: Optional[int] = None,
        github_token: Optional[str] = None,
    ) -> None:
        self.cache_root = (
            Path(cache_root) if cache_root else default_cache_root()
        ) / self.cache_subdir
        self.cache_root.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.max_findings = max_findings
        self.github_token = github_token
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "ZeroPath/0.9 contest-corpus"})

    # ------------------------------------------------------------------

    def scrape(self) -> tuple[list[ExternalIncidentRecord], ScrapeStats]:
        """Fetch (or load from cache), parse, return normalised records."""
        try:
            self._refresh_cache()
        except Exception as exc:
            logger.warning("%s: cache refresh failed: %s", self.source.value, exc)
        records: list[ExternalIncidentRecord] = []
        stats = ScrapeStats()
        for path in self._cached_inputs():
            try:
                source_records = self._parse_one(path)
            except Exception as exc:
                stats.errors.append(f"{path.name}: {type(exc).__name__}: {exc}")
                continue
            for rec in source_records:
                if self.max_findings is not None and len(records) >= self.max_findings:
                    return records, stats
                records.append(rec)
                stats.accepted += 1
        return records, stats

    @abstractmethod
    def _refresh_cache(self) -> None: ...

    @abstractmethod
    def _cached_inputs(self) -> Iterable[Path]: ...

    @abstractmethod
    def _parse_one(self, path: Path) -> list[ExternalIncidentRecord]: ...


# ---------------------------------------------------------------------------
# Code4rena scraper — enumerates code-423n4 org repos ending in -findings
# ---------------------------------------------------------------------------


# Findings headers in C4R reports look like:
#   ## [H-01] Reentrancy in withdraw()
#   ## [M-02] Missing slippage check
# Older reports also use bare `H-01` / `M-02` without brackets.
_C4R_HEADER_RE = re.compile(
    r"^#{1,3}\s*\[?(?P<sev>[HML]|QA|G)[-_](?P<num>\d{1,3})\]?\s*(?P<title>[^\n]+)$",
    re.MULTILINE,
)

_C4R_SEVERITY_MAP = {
    "H":  "high",
    "M":  "medium",
    "L":  "low",
    "QA": "informational",
    "G":  "informational",   # Gas
}

# Contest-repo naming: `YYYY-MM-{project}-findings`.
_C4R_REPO_PATTERN = re.compile(r"^(?P<date>\d{4}-\d{2})-(?P<project>.+)-findings$")


class Code4renaScraper(BaseScraper):
    """
    Enumerate `code-423n4` org repos with name ending in ``-findings``,
    fetch each repo's ``report.md``, parse aggregated findings.
    """

    source = IntelSource.CODE4RENA
    cache_subdir = "code4rena"

    ORG = "code-423n4"
    REPORT_FILES = ("report.md", "Report.md", "REPORT.md")

    # ------------------------------------------------------------------

    def _refresh_cache(self) -> None:
        repos = _list_org_repos(
            self._session, self.ORG,
            name_pattern=_C4R_REPO_PATTERN,
            token=self.github_token, timeout=self.timeout,
        )
        if not repos:
            logger.info("Code4rena: no contest repos discovered "
                         "(set GITHUB_TOKEN for the full backlog)")
        for repo in repos:
            name = repo.get("name")
            if not name:
                continue
            target = self.cache_root / f"{name}.md"
            if target.exists() and time.time() - target.stat().st_mtime < 7 * 86400:
                continue
            body = None
            for filename in self.REPORT_FILES:
                body = _fetch_raw_file(
                    self._session, self.ORG, name, filename,
                    branch=repo.get("default_branch", "main"),
                    timeout=self.timeout,
                )
                if body is not None:
                    break
            if body:
                target.write_text(body, encoding="utf-8")

    def _cached_inputs(self) -> Iterable[Path]:
        return sorted(self.cache_root.glob("*-findings.md"))

    def _parse_one(self, path: Path) -> list[ExternalIncidentRecord]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        # Cache file name = `{repo}.md` → strip trailing `.md` to recover repo name.
        repo_name = path.stem
        contest_id = repo_name
        return list(self._iter_findings(text, contest_id=contest_id))

    # ------------------------------------------------------------------

    def _iter_findings(
        self, text: str, *, contest_id: str,
    ) -> Iterable[ExternalIncidentRecord]:
        headers = list(_C4R_HEADER_RE.finditer(text))
        for i, m in enumerate(headers):
            severity_code = m.group("sev").upper()
            severity = _C4R_SEVERITY_MAP.get(severity_code, "medium")
            title = m.group("title").strip()
            section_start = m.end()
            section_end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
            body = text[section_start:section_end].strip()

            yield ExternalIncidentRecord(
                source=self.source,
                protocol=_protocol_from_c4r_repo(contest_id),
                attack_class=normalise_attack_class(title + " " + body[:800]),
                loss_usd=0,
                root_cause=_summarise_root_cause(body)[:500],
                affected_functions=_extract_function_refs(body)[:10],
                source_url=f"https://github.com/{self.ORG}/{contest_id}/blob/main/report.md",
                tags=[
                    "contest:code4rena",
                    f"severity:{severity_code}",
                    f"contest_id:{contest_id}",
                ],
                raw_payload={
                    "title": title,
                    "severity_code": severity_code,
                    "severity": severity,
                    "fingerprint": finding_fingerprint(
                        self.source.value, contest_id, title,
                    ),
                    "body_excerpt": body[:1500],
                },
            )


def _protocol_from_c4r_repo(repo_name: str) -> str:
    """Strip `YYYY-MM-` prefix and `-findings` suffix to get the project."""
    m = _C4R_REPO_PATTERN.match(repo_name)
    return m.group("project") if m else repo_name


# ---------------------------------------------------------------------------
# Sherlock scraper — enumerates sherlock-audit org judging repos
# ---------------------------------------------------------------------------


# Sherlock judging README headers look like `## Issue M-1: title` /
# `## H-1 - title` / `## Issue #1 — title`.
_SHERLOCK_HEADER_RE = re.compile(
    r"^#{1,3}\s*(?:Issue\s+)?\[?(?P<sev>[HMLI])[-_]?(?P<num>\d{1,3})\]?\s*[:\-—.]\s*(?P<title>[^\n]+)$",
    re.MULTILINE,
)
_SHERLOCK_SEVERITY_MAP = {
    "H": "high", "M": "medium", "L": "low", "I": "informational",
}

# Judging-repo naming: `YYYY-MM-{project}-judging`.
_SHERLOCK_REPO_PATTERN = re.compile(r"^(?P<date>\d{4}-\d{2})-(?P<project>.+)-judging$")


class SherlockScraper(BaseScraper):
    """
    Enumerate `sherlock-audit` org repos ending in ``-judging``, fetch
    each repo's ``README.md``, parse aggregated findings.

    The legacy `sherlock-protocol/sherlock-reports` repo holds PDFs we
    don't parse — Solodit covers those.
    """

    source = IntelSource.SHERLOCK
    cache_subdir = "sherlock"

    ORG = "sherlock-audit"
    README_FILES = ("README.md", "Readme.md", "readme.md")

    def _refresh_cache(self) -> None:
        repos = _list_org_repos(
            self._session, self.ORG,
            name_pattern=_SHERLOCK_REPO_PATTERN,
            token=self.github_token, timeout=self.timeout,
        )
        if not repos:
            logger.info("Sherlock: no judging repos discovered (set GITHUB_TOKEN)")
        for repo in repos:
            name = repo.get("name")
            if not name:
                continue
            target = self.cache_root / f"{name}.md"
            if target.exists() and time.time() - target.stat().st_mtime < 7 * 86400:
                continue
            body = None
            for filename in self.README_FILES:
                body = _fetch_raw_file(
                    self._session, self.ORG, name, filename,
                    branch=repo.get("default_branch", "main"),
                    timeout=self.timeout,
                )
                if body is not None:
                    break
            if body:
                target.write_text(body, encoding="utf-8")

    def _cached_inputs(self) -> Iterable[Path]:
        return sorted(self.cache_root.glob("*-judging.md"))

    def _parse_one(self, path: Path) -> list[ExternalIncidentRecord]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        contest_id = path.stem
        out: list[ExternalIncidentRecord] = []
        headers = list(_SHERLOCK_HEADER_RE.finditer(text))
        for i, m in enumerate(headers):
            severity_code = m.group("sev").upper()
            severity = _SHERLOCK_SEVERITY_MAP.get(severity_code, "medium")
            title = m.group("title").strip()
            section_start = m.end()
            section_end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
            body = text[section_start:section_end].strip()

            out.append(ExternalIncidentRecord(
                source=self.source,
                protocol=_protocol_from_sherlock_repo(contest_id),
                attack_class=normalise_attack_class(title + " " + body[:800]),
                loss_usd=0,
                root_cause=_summarise_root_cause(body)[:500],
                affected_functions=_extract_function_refs(body)[:10],
                source_url=f"https://github.com/{self.ORG}/{contest_id}/blob/main/README.md",
                tags=[
                    "contest:sherlock",
                    f"severity:{severity_code}",
                    f"contest_id:{contest_id}",
                ],
                raw_payload={
                    "title": title,
                    "severity_code": severity_code,
                    "severity": severity,
                    "fingerprint": finding_fingerprint(self.source.value, contest_id, title),
                    "body_excerpt": body[:1500],
                },
            ))
        return out


def _protocol_from_sherlock_repo(repo_name: str) -> str:
    m = _SHERLOCK_REPO_PATTERN.match(repo_name)
    return m.group("project") if m else repo_name


# ---------------------------------------------------------------------------
# Cantina scraper — metadata-only ingest from portfolio listing
# ---------------------------------------------------------------------------


# The Cantina web portfolio is a client-side-rendered SPA, so raw HTML
# fetches return an empty shell. The XML sitemap, however, is server-
# rendered and lists every portfolio review URL — the authoritative
# enumeration source for Cantina reviews.
_CANTINA_SITEMAP_URL_RE = re.compile(
    r"<loc>\s*https?://cantina\.xyz/portfolio/(?P<uuid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\s*</loc>",
    re.IGNORECASE,
)


class CantinaScraper(BaseScraper):
    """
    Enumerate Cantina security reviews via the XML sitemap.

    Why the sitemap instead of the portfolio HTML:
    `https://cantina.xyz/portfolio` is a client-side rendered SPA — raw
    HTML fetches return an empty shell with no portfolio data. The
    sitemap at `https://cantina.xyz/sitemap.xml` is server-rendered and
    lists every portfolio UUID, marked daily-fresh.

    Each finding's full text lives in a PDF behind a download wall, so
    this scraper ingests metadata-only records (review UUID + URL).
    Solodit covers the underlying findings — point ``--source solodit``
    at it for the detailed text.
    """

    source = IntelSource.CANTINA
    cache_subdir = "cantina"

    SITEMAP_URLS = (
        "https://cantina.xyz/sitemap.xml",     # index
        "https://cantina.xyz/sitemap-0.xml",   # actual URL list
    )

    def __init__(
        self,
        *,
        extra_report_urls: Optional[list[str]] = None,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.extra_urls = list(extra_report_urls or [])

    def _refresh_cache(self) -> None:
        for url in self.SITEMAP_URLS:
            cache_path = self._cache_path_for(url)
            if cache_path.exists() and time.time() - cache_path.stat().st_mtime < 86400:
                continue
            try:
                resp = self._session.get(url, timeout=self.timeout)
                resp.raise_for_status()
            except requests.RequestException as exc:
                logger.warning("Cantina: fetch %s failed: %s", url, exc)
                continue
            cache_path.write_text(resp.text, encoding="utf-8")
        # Also cache any extra report URLs the caller wants fetched verbatim.
        for url in self.extra_urls:
            cache_path = self._cache_path_for(url)
            if cache_path.exists() and time.time() - cache_path.stat().st_mtime < 86400:
                continue
            try:
                resp = self._session.get(url, timeout=self.timeout)
                resp.raise_for_status()
            except requests.RequestException:
                continue
            cache_path.write_text(resp.text, encoding="utf-8")

    def _cache_path_for(self, url: str) -> Path:
        safe = hashlib.sha1(url.encode("utf-8")).hexdigest()[:16]
        return self.cache_root / f"{safe}.xml"

    def _cached_inputs(self) -> Iterable[Path]:
        return sorted(self.cache_root.glob("*.xml"))

    def _parse_one(self, path: Path) -> list[ExternalIncidentRecord]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        seen_uuids: set[str] = set()
        out: list[ExternalIncidentRecord] = []
        for m in _CANTINA_SITEMAP_URL_RE.finditer(text):
            uuid = m.group("uuid")
            if uuid in seen_uuids:
                continue
            seen_uuids.add(uuid)
            out.append(ExternalIncidentRecord(
                source=self.source,
                # No human-readable label in the sitemap — use the UUID as
                # a stable handle; Solodit covers the named findings.
                protocol=f"cantina:{uuid[:8]}",
                attack_class="unknown",
                loss_usd=0,
                root_cause=f"Cantina security review {uuid} (metadata only — PDF)",
                source_url=f"https://cantina.xyz/portfolio/{uuid}",
                tags=[
                    "contest:cantina",
                    f"cantina_uuid:{uuid}",
                    "metadata_only",
                ],
                raw_payload={
                    "uuid": uuid,
                    "fingerprint": finding_fingerprint(
                        self.source.value, uuid, uuid,
                    ),
                },
            ))
        return out


# ---------------------------------------------------------------------------
# Solodit scraper — POST /api/v1/solodit/findings with API key
# ---------------------------------------------------------------------------


_SOLODIT_API_PAGE_SIZE = 100


class SoloditScraper(BaseScraper):
    """
    Pull Solodit's curated findings via the public API.

    The API requires an ``X-Cyfrin-API-Key`` header. Without one, the
    scraper falls back to a user-supplied local dump
    (``dump_path=...``). With either path you get 49 000+ findings
    aggregated across Code4rena, Cantina, Sherlock, Spearbit,
    OpenZeppelin, Trail of Bits, and many others — making Solodit the
    single richest source if you can authenticate.

    Endpoint reference: https://docs.solodit.cyfrin.io
    Rate limit: 20 requests / 60 seconds.
    """

    source = IntelSource.SOLODIT
    cache_subdir = "solodit"

    SEARCH_URL = "https://solodit.cyfrin.io/api/v1/solodit/findings"

    def __init__(
        self,
        *,
        dump_path: Optional[Path] = None,
        api_key: Optional[str] = None,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.dump_path = Path(dump_path) if dump_path else None
        self.api_key = api_key or os.environ.get("SOLODIT_API_KEY") or os.environ.get(
            "CYFRIN_API_KEY",
        )

    def _refresh_cache(self) -> None:
        if self.dump_path and self.dump_path.exists():
            target = self.cache_root / "dump.json"
            shutil.copy2(self.dump_path, target)
            return
        if not self.api_key:
            logger.info(
                "Solodit: no API key (SOLODIT_API_KEY env var or "
                "--solodit-api-key flag) and no dump_path — skipping"
            )
            return
        headers = {
            "Content-Type": "application/json",
            "X-Cyfrin-API-Key": self.api_key,
            "User-Agent": "ZeroPath/0.9 contest-corpus",
        }
        page = 1
        fetched_in_session = 0
        while True:
            cache_path = self.cache_root / f"page_{page:04d}.json"
            if cache_path.exists() and time.time() - cache_path.stat().st_mtime < 7 * 86400:
                page += 1
                if not (self.cache_root / f"page_{page:04d}.json").exists():
                    return
                continue
            payload = {"page": page, "pageSize": _SOLODIT_API_PAGE_SIZE, "filters": {}}
            try:
                resp = self._session.post(
                    self.SEARCH_URL, headers=headers, json=payload,
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                logger.warning("Solodit: page %d transport error: %s", page, exc)
                return
            if resp.status_code == 401:
                logger.warning("Solodit: 401 — check SOLODIT_API_KEY")
                return
            if resp.status_code == 429:
                logger.info("Solodit: rate-limited; sleeping 60s")
                time.sleep(60)
                continue
            if not resp.ok:
                logger.warning("Solodit: page %d HTTP %s", page, resp.status_code)
                return
            try:
                body = resp.json()
            except ValueError:
                return
            results = body.get("results") or body.get("findings") or []
            if not results:
                return
            cache_path.write_text(json.dumps(results), encoding="utf-8")
            fetched_in_session += len(results)
            if self.max_findings is not None and fetched_in_session >= self.max_findings:
                return
            if len(results) < _SOLODIT_API_PAGE_SIZE:
                return
            page += 1

    def _cached_inputs(self) -> Iterable[Path]:
        return sorted(self.cache_root.glob("*.json"))

    def _parse_one(self, path: Path) -> list[ExternalIncidentRecord]:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        items: list[dict] = raw if isinstance(raw, list) else [raw]
        out: list[ExternalIncidentRecord] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            title = (entry.get("title") or entry.get("name") or "").strip()
            if not title:
                continue
            protocol = (
                entry.get("protocol_category")
                or entry.get("protocol")
                or entry.get("project")
                or "unknown"
            )
            severity_raw = (entry.get("severity") or entry.get("impact") or "medium").lower()
            tags = entry.get("tags") or []
            attack_text = " ".join(tags) if tags else (
                entry.get("category") or entry.get("vulnerability_type") or ""
            )
            url = (
                entry.get("url")
                or entry.get("source_url")
                or (f"https://solodit.cyfrin.io/issues/{entry.get('slug')}" if entry.get("slug") else "")
            )
            body = entry.get("description") or entry.get("summary") or entry.get("body") or ""
            upstream = (entry.get("audit_firm") or entry.get("source") or "solodit").lower()
            out.append(ExternalIncidentRecord(
                source=self.source,
                protocol=str(protocol)[:120],
                attack_class=normalise_attack_class(str(attack_text) + " " + str(title)),
                loss_usd=_coerce_loss_usd(entry.get("loss_usd") or entry.get("funds_lost")),
                root_cause=str(body)[:500],
                source_url=str(url),
                tags=[
                    "contest:solodit",
                    f"severity:{severity_raw[:1].upper()}",
                    f"upstream:{upstream}",
                ] + [f"solodit_tag:{t}" for t in tags[:5] if isinstance(t, str)],
                raw_payload=entry,
            ))
        return out


# ---------------------------------------------------------------------------
# Spearbit scraper — github.com/spearbit/portfolio /pdfs/ filename parse
# ---------------------------------------------------------------------------


# Filenames look like:
#   Buck-Labs-Spearbit-Security-Review-January-2026.pdf
#   Morpho-Spearbit-Security-Review-September-2025.pdf
# We capture the project prefix + month + year.
_SPEARBIT_FILENAME_RE = re.compile(
    r"^(?P<project>.+?)-Spearbit-Security-Review-(?P<month>[A-Za-z]+)-(?P<year>\d{4})\.pdf$",
    re.IGNORECASE,
)


class SpearbitScraper(BaseScraper):
    """
    Enumerate `spearbit/portfolio` ``/pdfs/`` via the GitHub Contents API
    and parse filenames for metadata. We don't parse the PDFs themselves
    (would need pdfplumber + heavy deps); the metadata still gives the
    KG a record that "Spearbit audited Project X in Month/Year".
    """

    source = IntelSource.SPEARBIT
    cache_subdir = "spearbit"

    OWNER = "spearbit"
    REPO = "portfolio"
    PDFS_PATH = "pdfs"

    def _refresh_cache(self) -> None:
        cache_path = self.cache_root / "index.json"
        if cache_path.exists() and time.time() - cache_path.stat().st_mtime < 86400:
            return
        url = f"{GITHUB_API_BASE}/repos/{self.OWNER}/{self.REPO}/contents/{self.PDFS_PATH}"
        try:
            resp = self._session.get(
                url, headers=_github_headers(self.github_token),
                timeout=self.timeout,
            )
            resp.raise_for_status()
            payload = resp.json()
        except (requests.RequestException, ValueError) as exc:
            logger.warning("Spearbit: index fetch failed: %s", exc)
            return
        cache_path.write_text(json.dumps(payload), encoding="utf-8")

    def _cached_inputs(self) -> Iterable[Path]:
        return list(self.cache_root.glob("index.json"))

    def _parse_one(self, path: Path) -> list[ExternalIncidentRecord]:
        try:
            entries = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        out: list[ExternalIncidentRecord] = []
        for entry in entries if isinstance(entries, list) else []:
            name = entry.get("name", "")
            if not name.lower().endswith(".pdf"):
                continue
            m = _SPEARBIT_FILENAME_RE.match(name)
            if m:
                project = m.group("project").replace("-", " ").strip()
                month = m.group("month")
                year = m.group("year")
                review_date = f"{year}-{_MONTH_TO_NUM.get(month.lower(), '01')}-01"
            else:
                project = name.replace(".pdf", "")
                review_date = None
            html_url = entry.get("html_url") or entry.get("download_url") or ""
            out.append(ExternalIncidentRecord(
                source=self.source,
                protocol=project[:120],
                attack_class="unknown",
                loss_usd=0,
                incident_date=review_date,
                root_cause=f"Spearbit security review (metadata only — PDF report)",
                source_url=html_url,
                tags=["contest:spearbit", "metadata_only"],
                raw_payload={
                    "filename": name,
                    "project": project,
                    "fingerprint": finding_fingerprint(
                        self.source.value, "portfolio", name,
                    ),
                },
            ))
        return out


_MONTH_TO_NUM = {
    "january": "01", "february": "02", "march": "03", "april": "04",
    "may": "05", "june": "06", "july": "07", "august": "08",
    "september": "09", "october": "10", "november": "11", "december": "12",
}


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


_SCRAPER_REGISTRY: dict[IntelSource, type[BaseScraper]] = {
    IntelSource.CODE4RENA: Code4renaScraper,
    IntelSource.SHERLOCK: SherlockScraper,
    IntelSource.CANTINA: CantinaScraper,
    IntelSource.SOLODIT: SoloditScraper,
    IntelSource.SPEARBIT: SpearbitScraper,
}


@dataclass
class IngestReport:
    """Per-run aggregate of one or more scrapers."""

    by_source: dict[str, dict[str, Any]] = field(default_factory=dict)
    total_records: int = 0
    total_errors: int = 0


class ContestCorpusIngestor:
    """
    Drive every scraper, dedupe across runs via fingerprint, and persist
    into the KG through the existing :class:`IngestionEngine`.
    """

    def __init__(
        self,
        ingestion_engine: IngestionEngine,
        *,
        cache_root: Optional[Path] = None,
    ) -> None:
        self.ingestion_engine = ingestion_engine
        self.cache_root = cache_root

    def ingest(
        self,
        source: IntelSource,
        *,
        max_findings: Optional[int] = None,
        scraper_kwargs: Optional[dict] = None,
    ) -> dict[str, Any]:
        scraper_cls = _SCRAPER_REGISTRY.get(source)
        if scraper_cls is None:
            raise ValueError(f"no scraper registered for {source.value}")
        scraper = scraper_cls(
            cache_root=self.cache_root,
            max_findings=max_findings,
            **(scraper_kwargs or {}),
        )
        records, stats = scraper.scrape()
        ingested = 0
        for rec in records:
            try:
                self.ingestion_engine.ingest_external_incident(rec)
                ingested += 1
            except Exception as exc:
                stats.errors.append(f"ingest failed for {rec.protocol}: {exc}")
        return {
            "source": source.value,
            "records_parsed": stats.accepted,
            "records_ingested": ingested,
            "errors": stats.errors[:25],
            "error_count": len(stats.errors),
        }

    def seed_all(
        self,
        *,
        sources: Optional[Iterable[IntelSource]] = None,
        max_per_source: Optional[int] = None,
        scraper_kwargs: Optional[dict[IntelSource, dict]] = None,
    ) -> IngestReport:
        targets = list(sources) if sources else list(_SCRAPER_REGISTRY.keys())
        report = IngestReport()
        kwargs_map = scraper_kwargs or {}
        for src in targets:
            try:
                summary = self.ingest(
                    src, max_findings=max_per_source,
                    scraper_kwargs=kwargs_map.get(src),
                )
            except Exception as exc:
                summary = {
                    "source": src.value,
                    "records_parsed": 0,
                    "records_ingested": 0,
                    "errors": [f"{type(exc).__name__}: {exc}"],
                    "error_count": 1,
                }
            report.by_source[src.value] = summary
            report.total_records += summary["records_ingested"]
            report.total_errors += summary["error_count"]
        return report


# ---------------------------------------------------------------------------
# Helpers shared across scrapers
# ---------------------------------------------------------------------------


_HTML_TAG_RE = re.compile(r"<[^>]+>")
_HTML_ENTITY_MAP = {
    "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#39;": "'",
    "&nbsp;": " ",
}


def _strip_html(s: str) -> str:
    if not s:
        return ""
    out = _HTML_TAG_RE.sub("", s)
    for entity, repl in _HTML_ENTITY_MAP.items():
        out = out.replace(entity, repl)
    return re.sub(r"\s+", " ", out).strip()


def _summarise_root_cause(body: str) -> str:
    if not body:
        return ""
    for header in ("Vulnerability Detail", "Root Cause", "Description", "Summary", "Impact"):
        m = re.search(
            rf"^#{{1,4}}\s*{re.escape(header)}\s*\n+(.+?)(?=^#{{1,4}}\s|$)",
            body, re.IGNORECASE | re.DOTALL | re.MULTILINE,
        )
        if m:
            chunk = m.group(1).strip()
            if chunk:
                return chunk
    for para in re.split(r"\n\s*\n", body):
        cleaned = para.strip()
        if cleaned and not cleaned.startswith(("#", "```")):
            return cleaned
    return body[:300]


_FUNCTION_REF_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\(")
_RESERVED_FN_NAMES = {
    "if", "for", "while", "function", "require", "return", "uint256",
    "address", "bool", "import", "pragma", "modifier", "do", "else",
    "switch", "case", "try", "catch",
}


def _extract_function_refs(text: str) -> list[str]:
    if not text:
        return []
    names = []
    seen = set()
    for m in _FUNCTION_REF_RE.finditer(text):
        name = m.group(1)
        if name.lower() in _RESERVED_FN_NAMES:
            continue
        if name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names
