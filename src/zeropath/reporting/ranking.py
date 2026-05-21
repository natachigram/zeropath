"""
Finding ranker + deduplicator — Phase 9.

Two passes:

  1. **Dedup** — collapse findings with identical fingerprints into the
     highest-confidence representative. Different protocols with the same
     fingerprint stay distinct.
  2. **Rank** — sort by severity tier, then by profit (desc), then
     confidence (desc). After ranking, assign per-tier display numbers in
     the spec's ``[TIER-001]`` format.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Iterable

from zeropath.reporting.models import Finding, SeverityTier

logger = logging.getLogger(__name__)


def _dedup_key(f: Finding) -> tuple[str, str]:
    """Same fingerprint + same protocol = same finding for report purposes."""
    return (f.fingerprint or f"hyp::{f.hypothesis_id}", f.protocol_name)


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    """Return one Finding per (fingerprint, protocol). Keeps highest confidence."""
    buckets: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        buckets[_dedup_key(f)].append(f)
    out: list[Finding] = []
    for group in buckets.values():
        group.sort(key=lambda f: (-f.confidence, -f.profit_usd))
        out.append(group[0])
    return out


def _rank_key(f: Finding) -> tuple[int, float, float]:
    """Ranking key: lower is better. Severity rank → -profit → -confidence."""
    return (f.severity.rank, -f.profit_usd, -f.confidence)


def rank(findings: Iterable[Finding]) -> list[Finding]:
    """Sort findings by severity then profit/confidence."""
    return sorted(findings, key=_rank_key)


def assign_finding_numbers(findings: list[Finding]) -> list[Finding]:
    """
    In-place assignment of ``[TIER-NNN]`` style IDs. Counters reset per tier,
    1-indexed, zero-padded to three digits.
    """
    counters: dict[SeverityTier, int] = defaultdict(int)
    for f in findings:
        counters[f.severity] += 1
        n = counters[f.severity]
        f.finding_number = f"{f.severity.display}-{n:03d}"
    return findings


def deduplicate_and_rank(findings: Iterable[Finding]) -> list[Finding]:
    """Convenience: dedup → rank → assign display numbers."""
    deduped = deduplicate(findings)
    ranked = rank(deduped)
    return assign_finding_numbers(ranked)


# ---------------------------------------------------------------------------
# Severity rollups
# ---------------------------------------------------------------------------


def count_by_severity(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {tier.value: 0 for tier in SeverityTier}
    for f in findings:
        counts[f.severity.value] += 1
    return counts
