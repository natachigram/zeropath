"""Report export with judge gating."""

from __future__ import annotations

from pathlib import Path

from zeropath.core.errors import ReportNotReadyError
from zeropath.core.schemas import CandidateFinding, JudgeResult
from zeropath.core.storage import Storage


def export_report(
    storage: Storage,
    candidate_id: str,
    *,
    report_format: str = "code4rena",
    draft: bool = False,
) -> Path:
    candidate = storage.load_candidate(candidate_id)
    if candidate is None:
        raise KeyError(f"Candidate not found: {candidate_id}")
    judge = storage.load_judge_result(candidate_id)
    if judge is None or not judge.report_ready:
        if not draft:
            reason = "judge has not marked this candidate report-ready"
            if judge and judge.blocking_objections:
                reason = "; ".join(judge.blocking_objections)
            raise ReportNotReadyError(reason)
    report = render_report(candidate, judge, report_format=report_format, draft=draft)
    suffix = "draft" if draft else "final"
    return storage.append_artifact(
        Path("reports") / f"{candidate_id}_{report_format}_{suffix}.md",
        report,
        overwrite=True,
    )


def render_report(
    candidate: CandidateFinding,
    judge: JudgeResult | None,
    *,
    report_format: str,
    draft: bool,
) -> str:
    label = "DRAFT / NOT READY" if draft else "FINAL"
    severity = judge.severity if judge else candidate.severity_guess or "unknown"
    blockers = judge.blocking_objections if judge else ["Judge has not run."]
    next_steps = judge.required_next_steps if judge else ["Run `zeropath judge` before final reporting."]
    links = "\n".join(_format_location(loc) for loc in candidate.root_cause_locations) or "- TODO: add affected code links"
    txs = "\n".join(f"{idx + 1}. {step}" for idx, step in enumerate(candidate.transaction_sequence)) or "TODO"
    required_state = "\n".join(f"- {state}" for state in candidate.required_state) or "- TODO"
    evidence_notes = "\n".join(f"- {note}" for note in candidate.evidence.notes) or "- No additional notes."
    rejection = "\n".join(
        f"- {check.check_name}: {'passed' if check.passed else 'blocked'} - {check.reason}"
        for check in candidate.rejection_checks
    ) or "- Judge/rejection checks not complete."
    title = candidate.title

    return f"""# {label}: {title}

Format: {report_format}

## Severity

{severity}

## Links To Affected Code

{links}

## Vulnerability Details

Claim: {candidate.notes or 'TODO: complete details from evidence.'}

Affected invariant: {candidate.affected_invariant or 'unknown'}

Attacker model: {candidate.attacker_model or 'TODO'}

Required state:

{required_state}

Transaction sequence:

{txs}

## Impact

Type: {candidate.impact.impact_type}

Funds at risk: {candidate.impact.funds_at_risk}

Measured: {candidate.impact.measured}

Amount: {candidate.impact.amount or 'TODO'}

{candidate.impact.explanation}

## Proof Of Concept

PoC: {candidate.evidence.poc_path or 'TODO: no PoC artifact recorded'}

Forge result: {candidate.evidence.forge_result or 'not run'}

Trace: {candidate.evidence.trace_path or 'not recorded'}

## Recommended Mitigation

TODO: add protocol-specific mitigation after proof is complete.

## Evidence Summary

- Root cause lines present: {candidate.evidence.root_cause_lines_present}
- Attacker path present: {candidate.evidence.attacker_path_present}
- State preconditions present: {candidate.evidence.state_preconditions_present}
- Known issues checked: {candidate.evidence.known_issues_checked}
- Duplicate risk checked: {candidate.evidence.duplicate_risk_checked}
- Live config checked: {candidate.evidence.live_config_checked}
- Profit measured: {candidate.evidence.profit_measured}
- Chain ID: {candidate.evidence.chain_id or 'not checked'}
- Fork block: {candidate.evidence.fork_block or 'not checked'}

{evidence_notes}

## Rejection Checks

{rejection}

## Judge Status

Report ready: {judge.report_ready if judge else False}

Blocking objections:

{_bullets(blockers)}

Required next steps:

{_bullets(next_steps)}
"""


def _format_location(loc) -> str:
    line = f":{loc.line_start}" if loc.line_start else ""
    fn = f" `{loc.contract or ''}.{loc.function or ''}`".strip()
    return f"- {loc.file}{line} {fn}".rstrip()


def _bullets(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items) if items else "- None"
