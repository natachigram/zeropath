"""
Sherlock submission formatter.

Sherlock uses an impact × likelihood matrix to derive final severity, and
they aggregate findings by root cause. Submissions are Markdown with
inline lines-of-code refs.

Reference: https://docs.sherlock.xyz — schema based on 2024-2026 public
audit reports.
"""

from __future__ import annotations

from typing import Any

from zeropath.contest.models import ContestPlatform, Submission
from zeropath.contest.platforms.base import BasePlatformFormatter


# Impact ratings Sherlock accepts.
_SHERLOCK_IMPACT = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
}

# Likelihood is harder to infer from a static finding; default to "High"
# when confidence is high and there's no exotic precondition gating.
def _likelihood(confidence: float, num_preconditions: int) -> str:
    if confidence >= 0.80 and num_preconditions <= 2:
        return "High"
    if confidence >= 0.55:
        return "Medium"
    return "Low"


def _final_severity(impact: str, likelihood: str) -> str:
    """Sherlock's standard matrix collapse."""
    h = (impact, likelihood)
    if h == ("High", "High") or h == ("High", "Medium"):
        return "High"
    if h == ("High", "Low") or h == ("Medium", "High") or h == ("Medium", "Medium"):
        return "Medium"
    return "Low"


class SherlockFormatter(BasePlatformFormatter):
    platform = ContestPlatform.SHERLOCK

    def render(self, submission: Submission) -> dict[str, Any]:
        f = submission.finding
        impact = _SHERLOCK_IMPACT.get(self._norm_severity(f.severity), "Medium")
        likelihood = _likelihood(f.confidence, len(f.preconditions))
        final = _final_severity(impact, likelihood)
        return {
            "title": f.title,
            "impact": impact,
            "likelihood": likelihood,
            "final_severity": final,
            "markdown": self._render_markdown(submission, impact, likelihood, final),
            "lines_of_code": list(f.lines_of_code),
            "_zeropath": {
                "confidence": round(f.confidence, 3),
                "duplicate_likelihood": round(f.duplicate_likelihood, 3),
                "rank": submission.rank,
            },
        }

    @staticmethod
    def _render_markdown(
        submission: Submission, impact: str, likelihood: str, final: str,
    ) -> str:
        f = submission.finding
        parts: list[str] = [
            f"# {f.title}",
            "",
            f"**Impact:** {impact}",
            f"**Likelihood:** {likelihood}",
            f"**Final Severity:** {final}",
            "",
            "## Summary",
            "",
            f.description or f.impact or "_no summary_",
            "",
            "## Lines of Code",
            "",
        ]
        if f.lines_of_code:
            parts.extend(f"- {r}" for r in f.lines_of_code)
        else:
            parts.append("- (none provided)")
        parts.extend(["", "## Vulnerability Detail", ""])
        if f.attack_path:
            parts.extend(f"{i + 1}. {s}" for i, s in enumerate(f.attack_path))
        else:
            parts.append("_no detailed attack path_")
        parts.extend(["", "## Impact", "", f.impact or "_n/a_", ""])
        if f.preconditions:
            parts.extend(["## Preconditions", ""])
            parts.extend(f"- {p}" for p in f.preconditions)
            parts.append("")
        parts.extend(["## PoC", ""])
        if f.proof_of_concept_code:
            parts.extend(["```solidity", f.proof_of_concept_code, "```", ""])
        else:
            parts.extend(["_See attack path._", ""])
        parts.extend(["## Recommendation", "", f.recommendation or "_TBD_", ""])
        return "\n".join(parts).rstrip() + "\n"
