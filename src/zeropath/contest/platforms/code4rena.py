"""
Code4rena submission formatter.

Code4rena uses numbered Markdown findings with strict severity codes
(``H-01``, ``M-02``) and lines-of-code permalinks. Submissions go into
a per-warden GitHub repo; one finding == one Markdown file.

Reference: https://github.com/code4rena/reports — schema verified from
2024-2026 reports.
"""

from __future__ import annotations

from typing import Any

from zeropath.contest.models import ContestPlatform, Submission
from zeropath.contest.platforms.base import BasePlatformFormatter


_C4R_SEVERITY_CODE = {
    "critical": "H",     # C4R folds critical into high
    "high": "H",
    "medium": "M",
    "low": "L",
    "informational": "QA",
}


class Code4renaFormatter(BasePlatformFormatter):
    platform = ContestPlatform.CODE4RENA

    def render(self, submission: Submission) -> dict[str, Any]:
        f = submission.finding
        severity = self._norm_severity(f.severity)
        code = _C4R_SEVERITY_CODE.get(severity, "M")
        markdown = self._render_markdown(submission, severity_code=code)
        return {
            "severity_code": code,
            "severity": severity,
            "title": f.title,
            "filename": self._filename(submission, code),
            "markdown": markdown,
            "lines_of_code": list(f.lines_of_code),
            "_zeropath": {
                "rank": submission.rank,
                "confidence": round(f.confidence, 3),
                "duplicate_likelihood": round(f.duplicate_likelihood, 3),
            },
        }

    # ------------------------------------------------------------------

    @staticmethod
    def _filename(submission: Submission, code: str) -> str:
        slug = "".join(
            c if c.isalnum() else "-" for c in submission.finding.title.lower()
        )[:60].strip("-")
        return f"{code}-{submission.rank:02d}-{slug}.md"

    @staticmethod
    def _render_markdown(submission: Submission, *, severity_code: str) -> str:
        f = submission.finding
        parts: list[str] = [
            f"# [{severity_code}-{submission.rank:02d}] {f.title}",
            "",
            f"**Severity:** {f.severity.upper()}",
            f"**Attack class:** `{f.attack_class}`",
            "",
            "## Lines of Code",
            "",
        ]
        parts.append(
            "\n".join(f"- {r}" for r in f.lines_of_code) if f.lines_of_code
            else "- (none provided)"
        )
        parts.extend([
            "",
            "## Description",
            "",
            f.description or "_no description_",
            "",
            "## Impact",
            "",
            f.impact or "_no impact statement_",
            "",
        ])
        if f.attack_path:
            parts.extend(["## Attack Path", ""])
            parts.extend(f"{i + 1}. {step}" for i, step in enumerate(f.attack_path))
            parts.append("")
        if f.preconditions:
            parts.extend(["## Preconditions", ""])
            parts.extend(f"- {p}" for p in f.preconditions)
            parts.append("")
        parts.extend(["## Proof of Concept", ""])
        if f.proof_of_concept_code:
            parts.extend(["```solidity", f.proof_of_concept_code, "```", ""])
        else:
            parts.extend(["_See attack path; PoC available on request._", ""])
        if f.proof_of_concept_run_log:
            parts.extend([
                "<details><summary>Foundry run output</summary>",
                "",
                "```",
                f.proof_of_concept_run_log[:4000],
                "```",
                "",
                "</details>",
                "",
            ])
        parts.extend([
            "## Recommended Mitigation",
            "",
            f.recommendation or "_specific fix TBD_",
            "",
        ])
        if f.historical_precedents:
            parts.extend(["## Historical Precedent", ""])
            for ref in f.historical_precedents[:3]:
                parts.append(
                    f"- **{ref.get('protocol', 'unknown')}** "
                    f"({ref.get('incident_date', 'n/a')}) — "
                    f"${ref.get('loss_usd', 0):,} loss"
                )
            parts.append("")
        return "\n".join(parts).rstrip() + "\n"
