"""
External threat-intelligence ingestor — Phase 8.

Spec (phases.md, PHASE 8 critical additions, "External threat intelligence"):
    "Ingest and normalize data from:
       - DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)
       - Rekt.news
       - Immunefi post-mortems
       - Chainalysis on-chain attribution data (where available)
     Store as first-class graph nodes. Every inferred invariant and validated
     exploit should be linked to relevant historical incidents."

The ingestor reads upstream feeds — repo files, JSON dumps, or HTTP — and
normalises them into :class:`ExternalIncidentRecord` rows ready for the KG.
Each source has a dedicated parser so future schema drift only touches one
module.

Network access is *optional*: the parsers expose ``parse_*`` methods that
take an iterable of upstream entries, so tests (and offline runs) pass
fixtures directly. Live fetching lives in tiny ``fetch_*`` helpers that any
caller can replace.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Iterable, Optional

import requests

from zeropath.knowledge.models import ExternalIncidentRecord, IntelSource

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Attack-class normalisation
# ---------------------------------------------------------------------------


_ATTACK_CLASS_KEYWORDS: list[tuple[tuple[str, ...], str]] = [
    (("flashloan", "flash-loan", "flash loan"),    "flash_loan"),
    (("oracle", "price manipulation", "twap"),     "oracle_manipulation"),
    (("reentrancy", "re-entrancy", "reenter"),     "reentrancy"),
    (("access control", "permission", "auth"),     "access_control"),
    (("governance", "proposal", "voting"),         "governance"),
    (("composability", "cross-protocol"),          "composability"),
    (("integer", "overflow", "underflow", "math"), "integer_math"),
    (("rounding", "precision"),                    "integer_math"),
]


def normalise_attack_class(text: str) -> str:
    """Map free-form tags / titles to a Phase 3 AttackClass.value."""
    if not text:
        return "unknown"
    haystack = text.lower()
    for keywords, cls in _ATTACK_CLASS_KEYWORDS:
        if any(kw in haystack for kw in keywords):
            return cls
    return "unknown"


# Fallback ETH→USD conversion when the upstream feed reports losses in ETH
# rather than dollars. Used as a coarse normalisation only — the ExploitRecord
# always keeps the original string in ``raw_payload`` so a caller can re-price
# later with a live oracle if needed.
DEFAULT_ETH_USD_RATE = 3000


def _coerce_loss_usd(value: Any, *, eth_usd_rate: int = DEFAULT_ETH_USD_RATE) -> int:
    """
    Normalise free-form loss strings into integer USD.

    Accepts:
      * raw int / float
      * '$1.2M' / '$197M' / '$32k'  — dollar-denominated, k/M/B suffixes
      * '32.8 ETH' / '1.2 eth'      — ETH-denominated → multiplied by
                                        DEFAULT_ETH_USD_RATE
      * '~$1.2 million'             — words tolerated, multiplier extracted
    """
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    if not isinstance(value, str):
        return 0
    raw = value.strip().lower()
    # Detect ETH denomination before stripping $/letters.
    is_eth = bool(re.search(r"\beth\b", raw))
    s = raw.replace("$", "").replace(",", "").replace("~", "").replace("≈", "")
    # Strip currency words AFTER detecting denomination.
    for word in ("eth", "ether", "usd", "dollars", "dollar"):
        s = re.sub(rf"\b{word}\b", "", s)
    s = s.strip()
    multiplier = 1
    if s.endswith("k"):
        multiplier = 1_000
        s = s[:-1].strip()
    elif s.endswith("m") or s.endswith(" million"):
        multiplier = 1_000_000
        s = s.removesuffix(" million").removesuffix("m").strip()
    elif s.endswith("b") or s.endswith(" billion"):
        multiplier = 1_000_000_000
        s = s.removesuffix(" billion").removesuffix("b").strip()
    try:
        amount = float(s) * multiplier
    except (ValueError, TypeError):
        return 0
    if is_eth:
        amount *= eth_usd_rate
    return int(amount)


_ETH_ADDRESS_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")


def _extract_addresses(payload: dict) -> list[str]:
    out: set[str] = set()
    blob = json.dumps(payload)
    out.update(m.group(0) for m in _ETH_ADDRESS_RE.finditer(blob))
    return sorted(out)


# ---------------------------------------------------------------------------
# Per-source parsers
# ---------------------------------------------------------------------------


@dataclass
class ParseStats:
    """Per-batch parse telemetry — returned by ``parse_*`` helpers."""

    accepted: int = 0
    skipped: int = 0
    errors: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.errors is None:
            self.errors = []


class DeFiHackLabsParser:
    """
    DeFiHackLabs repo entries (github.com/SunWeb3Sec/DeFiHackLabs).

    The repo is markdown-heavy, but its ``Info.md`` / per-year JSON files
    have a stable schema-ish layout: ``protocol``, ``date``, ``loss``,
    ``attack``, ``tx``, ``article``, ``description``. We accept either.
    """

    source = IntelSource.DEFIHACKLABS

    def parse_many(
        self, entries: Iterable[dict]
    ) -> tuple[list[ExternalIncidentRecord], ParseStats]:
        out: list[ExternalIncidentRecord] = []
        stats = ParseStats()
        for entry in entries:
            try:
                rec = self.parse_one(entry)
                if rec is None:
                    stats.skipped += 1
                    continue
                out.append(rec)
                stats.accepted += 1
            except Exception as exc:
                stats.errors.append(f"{type(exc).__name__}: {exc}")
        return out, stats

    def parse_one(self, entry: dict) -> Optional[ExternalIncidentRecord]:
        protocol = (
            entry.get("protocol")
            or entry.get("target")
            or entry.get("name")
        )
        if not protocol:
            return None
        attack_text = (
            entry.get("attack")
            or entry.get("vulnerability")
            or entry.get("description", "")
        )
        return ExternalIncidentRecord(
            source=self.source,
            protocol=str(protocol),
            chain=str(entry.get("chain", "ethereum")),
            incident_date=entry.get("date"),
            attack_class=normalise_attack_class(str(attack_text)),
            loss_usd=_coerce_loss_usd(entry.get("loss") or entry.get("loss_usd")),
            root_cause=str(attack_text)[:500],
            source_url=str(entry.get("article", "") or entry.get("source_url", "")),
            tags=list(entry.get("tags", []) or []),
            affected_addresses=_extract_addresses(entry),
            raw_payload=entry,
        )

    # ------------------------------------------------------------------
    # Live fetchers (no credentials required)
    # ------------------------------------------------------------------

    _README_URL = (
        "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/"
        "main/README.md"
    )

    # Modern DeFiHackLabs format (verified 2026-05): each incident is a
    # markdown header section:
    #
    #     ### 20260120 Makina - Price Oracle Manipulation
    #     ### Lost: $1.2M
    #     ```sh ... ```
    #     [Makina_exp.sol](src/test/2026-01/Makina_exp.sol)
    #     ### Link reference
    #     https://reference-url
    #     ---
    _INCIDENT_HEADER_RE = re.compile(
        r"^###\s+(?P<date>20\d{6})\s+(?P<protocol>[^-\n]+?)\s*-\s*(?P<attack>[^\n]+)$",
        re.MULTILINE,
    )
    _LOSS_RE = re.compile(r"^###\s+Lost:\s*(?P<loss>[^\n]+)$", re.MULTILINE)
    _REFERENCE_URL_RE = re.compile(
        r"^###\s+Link reference\s*\n+(?P<url>https?://[^\s\n]+)", re.MULTILINE,
    )

    @classmethod
    def fetch_live_entries(cls, timeout: int = 15) -> list[dict]:
        """
        Parse the DeFiHackLabs README for its incident sections.

        The repo doesn't ship a stable JSON index. Its README lists every
        incident as a markdown section with a ``### YYYYMMDD PROJECT -
        ATTACK_TYPE`` header followed by ``### Lost: AMOUNT`` and a
        reference URL. This method walks those sections and produces
        dicts compatible with :meth:`parse_one`.

        Returns an empty list on network failure so callers can degrade.
        """
        try:
            resp = requests.get(cls._README_URL, timeout=timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            logger.warning("DeFiHackLabs fetch failed: %s", exc)
            return []

        text = resp.text
        headers = list(cls._INCIDENT_HEADER_RE.finditer(text))
        entries: list[dict] = []
        for i, m in enumerate(headers):
            start = m.end()
            end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
            chunk = text[start:end]

            loss_match = cls._LOSS_RE.search(chunk)
            url_match = cls._REFERENCE_URL_RE.search(chunk)

            yyyymmdd = m.group("date")
            iso_date = f"{yyyymmdd[:4]}-{yyyymmdd[4:6]}-{yyyymmdd[6:8]}"
            entries.append({
                "protocol": m.group("protocol").strip(),
                "date": iso_date,
                "loss": loss_match.group("loss").strip() if loss_match else "",
                "attack": m.group("attack").strip(),
                "article": url_match.group("url").strip() if url_match else "",
            })
        logger.info("DeFiHackLabs fetch returned %d entries", len(entries))
        return entries


class RektNewsParser:
    """
    Rekt.news "leaderboard" entries.

    Rekt publishes a CSV/JSON leaderboard with fields: ``name``, ``date``,
    ``funds_lost``, ``tags``, ``url``. Tags are how we infer attack class.
    """

    source = IntelSource.REKT

    def parse_many(
        self, entries: Iterable[dict]
    ) -> tuple[list[ExternalIncidentRecord], ParseStats]:
        out: list[ExternalIncidentRecord] = []
        stats = ParseStats()
        for entry in entries:
            try:
                rec = self.parse_one(entry)
                if rec is None:
                    stats.skipped += 1
                    continue
                out.append(rec)
                stats.accepted += 1
            except Exception as exc:
                stats.errors.append(f"{type(exc).__name__}: {exc}")
        return out, stats

    def parse_one(self, entry: dict) -> Optional[ExternalIncidentRecord]:
        name = entry.get("name") or entry.get("project")
        if not name:
            return None
        tags = entry.get("tags") or []
        attack_text = " ".join(tags) if tags else (entry.get("summary") or "")
        return ExternalIncidentRecord(
            source=self.source,
            protocol=str(name),
            chain=str(entry.get("chain", "ethereum")),
            incident_date=entry.get("date") or entry.get("incident_date"),
            attack_class=normalise_attack_class(attack_text),
            loss_usd=_coerce_loss_usd(entry.get("funds_lost") or entry.get("loss")),
            root_cause=str(entry.get("summary", ""))[:500],
            source_url=str(entry.get("url", "")),
            tags=list(tags),
            affected_addresses=_extract_addresses(entry),
            raw_payload=entry,
        )


class ImmunefiParser:
    """
    Immunefi post-mortem records. Their public dataset uses ``project``,
    ``date``, ``loss_usd``, ``root_cause``, ``vulnerability_type``,
    ``links`` (list).
    """

    source = IntelSource.IMMUNEFI

    def parse_many(
        self, entries: Iterable[dict]
    ) -> tuple[list[ExternalIncidentRecord], ParseStats]:
        out: list[ExternalIncidentRecord] = []
        stats = ParseStats()
        for entry in entries:
            try:
                rec = self.parse_one(entry)
                if rec is None:
                    stats.skipped += 1
                    continue
                out.append(rec)
                stats.accepted += 1
            except Exception as exc:
                stats.errors.append(f"{type(exc).__name__}: {exc}")
        return out, stats

    def parse_one(self, entry: dict) -> Optional[ExternalIncidentRecord]:
        project = entry.get("project") or entry.get("protocol")
        if not project:
            return None
        attack_text = entry.get("vulnerability_type", "") or entry.get("root_cause", "")
        links = entry.get("links") or []
        url = links[0] if links else entry.get("source_url", "")
        return ExternalIncidentRecord(
            source=self.source,
            protocol=str(project),
            chain=str(entry.get("chain", "ethereum")),
            incident_date=entry.get("date") or entry.get("incident_date"),
            attack_class=normalise_attack_class(str(attack_text)),
            loss_usd=_coerce_loss_usd(entry.get("loss_usd") or entry.get("loss")),
            root_cause=str(entry.get("root_cause", ""))[:500],
            source_url=str(url),
            tags=list(entry.get("tags", []) or []),
            affected_addresses=_extract_addresses(entry),
            raw_payload=entry,
        )


# ---------------------------------------------------------------------------
# Aggregating ingestor
# ---------------------------------------------------------------------------


class ThreatIntelIngestor:
    """
    Façade that dispatches to the right parser per source and writes results
    into the supplied store via the :class:`IngestionEngine`.
    """

    _PARSER_FOR: dict[IntelSource, Any] = {
        IntelSource.DEFIHACKLABS: DeFiHackLabsParser(),
        IntelSource.REKT: RektNewsParser(),
        IntelSource.IMMUNEFI: ImmunefiParser(),
    }

    def __init__(self, ingestion_engine) -> None:
        self.ingestion_engine = ingestion_engine

    # ------------------------------------------------------------------

    def ingest_entries(
        self,
        source: IntelSource,
        entries: Iterable[dict],
    ) -> tuple[list[ExternalIncidentRecord], ParseStats]:
        parser = self._PARSER_FOR.get(source)
        if parser is None:
            raise ValueError(f"no parser registered for source: {source}")
        records, stats = parser.parse_many(entries)
        for r in records:
            self.ingestion_engine.ingest_external_incident(r)
        logger.info(
            "Threat-intel ingest from %s: accepted=%d, skipped=%d, errors=%d",
            source.value, stats.accepted, stats.skipped, len(stats.errors),
        )
        return records, stats

    def normalise(
        self,
        source: IntelSource,
        entries: Iterable[dict],
    ) -> list[ExternalIncidentRecord]:
        """Like ``ingest_entries`` but doesn't write to the store."""
        parser = self._PARSER_FOR.get(source)
        if parser is None:
            raise ValueError(f"no parser registered for source: {source}")
        records, _ = parser.parse_many(entries)
        return records

    # ------------------------------------------------------------------
    # Live fetchers (only DeFiHackLabs requires no credentials)
    # ------------------------------------------------------------------

    def ingest_defihacklabs_live(
        self, *, timeout: int = 15,
    ) -> tuple[list[ExternalIncidentRecord], ParseStats]:
        """
        One-shot helper: pull DeFiHackLabs incidents straight from GitHub
        and ingest them. Returns ``([], ParseStats())`` on network failure
        so callers can branch cleanly.
        """
        entries = DeFiHackLabsParser.fetch_live_entries(timeout=timeout)
        if not entries:
            return [], ParseStats()
        return self.ingest_entries(IntelSource.DEFIHACKLABS, entries)
