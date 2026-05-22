"""
Spec Miner — Contest mode (Phase 2.5).

Bugs in audit contests cluster heavily in the gap between **what the docs
say** and **what the code does**. This module extracts every claimed
invariant from:

  * NatSpec comments on contracts / functions / events
  * README.md (and the audit-scope README at the repo root)
  * `docs/*.md` whitepapers / specification files
  * Inline ``// invariant: ...`` and ``/// @custom:invariant`` annotations

Two output channels:

  * Pure regex-based extraction — runs without any LLM, fast, deterministic.
    Catches explicit ``MUST`` / ``MUST NOT`` / ``always`` claims.
  * Optional LLM-augmented extraction — pulls fuzzy claims like "shares
    are minted 1:1 against assets on first deposit" out of prose.

The :class:`SpecMismatchDetector` then compares the claimed invariants
against Phase 2 inferred invariants and flags divergences as a new
finding source — these are gold in contests.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from pydantic import BaseModel, ConfigDict, Field

from zeropath.invariants.models import Invariant, InvariantReport

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


class ClaimedInvariant(BaseModel):
    """One natural-language invariant claim extracted from docs / code."""

    model_config = ConfigDict(populate_by_name=True)

    claim: str
    source: str = "natspec"      # natspec | readme | whitepaper | comment
    source_location: str = ""    # path:line OR doc-section
    involved_functions: list[str] = Field(default_factory=list)
    predicate: str = ""          # best-effort formal-ish translation
    violation_severity: str = "medium"


class SpecMismatch(BaseModel):
    """A claimed invariant the Phase 2 detectors did NOT confirm."""

    model_config = ConfigDict(populate_by_name=True)

    claim: ClaimedInvariant
    matched_phase2_invariant_id: Optional[str] = None
    mismatch_kind: str = "missing"   # missing | weaker | contradicted
    notes: str = ""


# ---------------------------------------------------------------------------
# Regex-only extractor
# ---------------------------------------------------------------------------


# NatSpec tag patterns that commonly carry invariants.
_NATSPEC_TAG_RE = re.compile(
    r"(?:///|\*)\s*@(?P<tag>notice|dev|custom:invariant|custom:security)"
    r"\s+(?P<body>[^\n]+(?:\n\s*(?:///|\*)\s+[^@\n][^\n]*)*)",
    re.IGNORECASE,
)

# In-source invariant annotations (Foundry/Halmos style).
_INLINE_INVARIANT_RE = re.compile(
    r"//\s*invariant\s*[:=]\s*(?P<body>[^\n]+)", re.IGNORECASE,
)

# MUST / MUST NOT / ALWAYS / NEVER style claims in prose.
_CLAIM_KEYWORDS_RE = re.compile(
    r"(?P<line>[^\n]*\b(?:MUST(?:\s+NOT)?|SHALL(?:\s+NOT)?|always|never|"
    r"only the\s+\w+|cannot|may not|required to|guaranteed to)\b[^\n]*)",
    re.IGNORECASE,
)


def _strip_natspec_decor(body: str) -> str:
    """Collapse multi-line NatSpec bodies into one sentence."""
    lines = []
    for line in body.splitlines():
        stripped = line.strip()
        stripped = stripped.lstrip("/").lstrip("*").strip()
        if stripped:
            lines.append(stripped)
    return " ".join(lines)


def _severity_for_claim(text: str) -> str:
    """Heuristic mapping of claim language → expected violation severity."""
    lower = text.lower()
    if any(kw in lower for kw in (
        "drain", "steal", "lock funds", "burn supply",
        "ownership transfer", "upgrade", "delete state",
    )):
        return "critical"
    if any(kw in lower for kw in (
        "must not", "shall not", "never", "cannot",
        "only the owner", "only admin", "only governance",
    )):
        return "high"
    if any(kw in lower for kw in ("must", "shall", "always", "required to")):
        return "medium"
    return "low"


def _extract_function_names(text: str) -> list[str]:
    """Best-effort scrape of function names referenced in a claim."""
    return list({m.group(0) for m in re.finditer(r"\b[a-z][A-Za-z0-9_]*\(\)", text)})


class RegexSpecExtractor:
    """Stdlib-only extractor — no LLM required."""

    def extract_from_solidity(self, source: str, file_path: str = "") -> list[ClaimedInvariant]:
        out: list[ClaimedInvariant] = []
        for m in _NATSPEC_TAG_RE.finditer(source):
            body = _strip_natspec_decor(m.group("body"))
            if not body:
                continue
            tag = m.group("tag").lower()
            line_no = source[: m.start()].count("\n") + 1
            # Skip docs that are just describing parameters
            if tag in ("notice", "dev") and not _CLAIM_KEYWORDS_RE.search(body):
                # Keep only if it's an obvious "must" / "always" claim
                continue
            out.append(ClaimedInvariant(
                claim=body[:500],
                source="natspec",
                source_location=f"{file_path}:{line_no}",
                involved_functions=_extract_function_names(body),
                violation_severity=_severity_for_claim(body),
            ))
        for m in _INLINE_INVARIANT_RE.finditer(source):
            body = m.group("body").strip()
            line_no = source[: m.start()].count("\n") + 1
            out.append(ClaimedInvariant(
                claim=body[:500],
                source="comment",
                source_location=f"{file_path}:{line_no}",
                predicate=body[:200],
                violation_severity="high",
            ))
        return out

    def extract_from_markdown(self, text: str, file_path: str = "") -> list[ClaimedInvariant]:
        out: list[ClaimedInvariant] = []
        for m in _CLAIM_KEYWORDS_RE.finditer(text or ""):
            line = m.group("line").strip()
            if len(line) < 12:
                continue
            line_no = (text or "")[: m.start()].count("\n") + 1
            out.append(ClaimedInvariant(
                claim=line[:500],
                source="readme" if file_path.lower().endswith("readme.md") else "whitepaper",
                source_location=f"{file_path}:{line_no}",
                violation_severity=_severity_for_claim(line),
            ))
        return out


# ---------------------------------------------------------------------------
# LLM-augmented extractor (optional)
# ---------------------------------------------------------------------------


class LLMSpecExtractor:
    """
    Use an :class:`LLMProvider` to mine fuzzy invariants out of prose.

    Falls back to no-op when the provider is unavailable.
    """

    def __init__(self, provider, *, max_input_chars: int = 12_000) -> None:
        self.provider = provider
        self.max_input_chars = max_input_chars

    def extract(
        self,
        *,
        file_path: str,
        natspec_block: str = "",
        readme_excerpt: str = "",
        docs_excerpt: str = "",
    ) -> list[ClaimedInvariant]:
        # Defer import to keep the regex extractor zero-dep.
        from zeropath.llm.prompts import SYSTEM_SPEC_EXTRACTOR, spec_extraction_prompt

        if not self.provider or not self.provider.is_available:
            return []

        prompt = spec_extraction_prompt(
            file_path=file_path,
            natspec_block=natspec_block[: self.max_input_chars],
            readme_excerpt=readme_excerpt[: self.max_input_chars],
            docs_excerpt=docs_excerpt[: self.max_input_chars],
        )
        try:
            resp = self.provider.complete(
                system=SYSTEM_SPEC_EXTRACTOR,
                messages=[{"role": "user", "content": prompt}],
                tools=None,
                max_tokens=2048,
                temperature=0.0,
            )
        except Exception as exc:
            logger.warning("LLMSpecExtractor failed: %s", exc)
            return []

        text = (resp.content or "").strip()
        if not text:
            return []
        # Be lenient about Markdown code fences.
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.MULTILINE).strip()
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return []
        out: list[ClaimedInvariant] = []
        for row in payload if isinstance(payload, list) else []:
            try:
                out.append(ClaimedInvariant(
                    claim=str(row.get("claim", ""))[:500],
                    source=str(row.get("source", "whitepaper")),
                    source_location=str(row.get("source_location") or file_path),
                    involved_functions=list(row.get("involved_functions") or []),
                    predicate=str(row.get("predicate", ""))[:200],
                    violation_severity=str(row.get("violation_severity", "medium")).lower(),
                ))
            except Exception:
                continue
        return out


# ---------------------------------------------------------------------------
# Top-level miner
# ---------------------------------------------------------------------------


@dataclass
class SpecMinerResult:
    claimed_invariants: list[ClaimedInvariant] = field(default_factory=list)
    files_processed: list[str] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)


class SpecMiner:
    """
    Crawl a repo, run extractors, return claimed invariants.

    Parameters
    ----------
    repo_root : Path
        Audit scope root.
    use_llm : bool
        Run the LLM-augmented extractor in addition to the regex one.
    llm_provider : LLMProvider | None
        Pluggable LLM for the augmented path. Ignored if ``use_llm=False``.
    """

    def __init__(
        self,
        repo_root: Path | str,
        *,
        use_llm: bool = False,
        llm_provider=None,
    ) -> None:
        self.repo_root = Path(repo_root)
        self.regex = RegexSpecExtractor()
        self.use_llm = use_llm
        self.llm = LLMSpecExtractor(llm_provider) if use_llm and llm_provider else None

    # ------------------------------------------------------------------

    def mine(
        self,
        *,
        contract_globs: Iterable[str] = ("**/*.sol",),
        doc_globs: Iterable[str] = ("README.md", "README", "docs/**/*.md", "spec/**/*.md"),
    ) -> SpecMinerResult:
        result = SpecMinerResult()

        # 1. Solidity NatSpec + inline invariants
        for glob in contract_globs:
            for path in self.repo_root.glob(glob):
                if not path.is_file():
                    continue
                try:
                    source = path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    result.skipped_files.append(str(path))
                    continue
                rel = str(path.relative_to(self.repo_root))
                claims = self.regex.extract_from_solidity(source, file_path=rel)
                if self.llm:
                    claims.extend(self.llm.extract(
                        file_path=rel, natspec_block=source,
                    ))
                if claims:
                    result.claimed_invariants.extend(claims)
                result.files_processed.append(rel)

        # 2. Markdown docs
        for glob in doc_globs:
            for path in self.repo_root.glob(glob):
                if not path.is_file():
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    result.skipped_files.append(str(path))
                    continue
                rel = str(path.relative_to(self.repo_root))
                claims = self.regex.extract_from_markdown(text, file_path=rel)
                if self.llm:
                    is_readme = "readme" in rel.lower()
                    claims.extend(self.llm.extract(
                        file_path=rel,
                        readme_excerpt=text if is_readme else "",
                        docs_excerpt=text if not is_readme else "",
                    ))
                if claims:
                    result.claimed_invariants.extend(claims)
                result.files_processed.append(rel)

        return result


# ---------------------------------------------------------------------------
# Spec/impl mismatch detector
# ---------------------------------------------------------------------------


class SpecMismatchDetector:
    """
    Compare claimed invariants to Phase 2 inferred invariants.

    A *match* is a claim whose tokens overlap heavily with an existing
    invariant. A *miss* is a claim with no match — these are bug candidates
    because they suggest the protocol's documented behaviour isn't being
    enforced by code patterns Phase 2 already catches.
    """

    def __init__(self, *, min_overlap: int = 2) -> None:
        self.min_overlap = min_overlap

    def detect(
        self,
        *,
        claimed: Iterable[ClaimedInvariant],
        inferred_report: InvariantReport,
    ) -> list[SpecMismatch]:
        inferred = list(inferred_report.invariants)
        out: list[SpecMismatch] = []
        for c in claimed:
            best_match, score = self._best_match(c, inferred)
            if best_match is None or score < self.min_overlap:
                out.append(SpecMismatch(
                    claim=c,
                    mismatch_kind="missing",
                    notes=(
                        "No Phase 2 invariant catches this claim. Likely "
                        "spec/implementation gap — manual review required."
                    ),
                ))
        return out

    @staticmethod
    def _best_match(
        claim: ClaimedInvariant, inferred: list[Invariant],
    ) -> tuple[Optional[Invariant], int]:
        claim_tokens = {
            t.lower() for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]+", claim.claim)
        }
        # Toss common english words
        claim_tokens -= {
            "the", "is", "are", "must", "shall", "always", "never",
            "should", "this", "that", "and", "or", "of", "in", "to", "be",
            "a", "an", "for", "by", "with", "without", "if", "then",
        }
        best, best_score = None, 0
        for inv in inferred:
            inv_text = " ".join([
                inv.description or "",
                " ".join(inv.functions_involved or []),
                " ".join(inv.contracts_involved or []),
            ])
            inv_tokens = {
                t.lower() for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]+", inv_text)
            }
            score = len(claim_tokens & inv_tokens)
            if score > best_score:
                best, best_score = inv, score
        return best, best_score


# ---------------------------------------------------------------------------
# Helper: build prompt-ready summary string from a list of claims
# ---------------------------------------------------------------------------


def render_claims_for_prompt(claims: Iterable[ClaimedInvariant], *, limit: int = 30) -> str:
    """Compact Markdown rendering used by the LLM Reasoner system prompt."""
    rows = list(claims)[:limit]
    if not rows:
        return ""
    lines: list[str] = []
    for c in rows:
        lines.append(
            f"- [{c.violation_severity.upper()}] {c.claim} "
            f"_(source: {c.source}; loc: {c.source_location})_"
        )
    return "\n".join(lines)
