"""Report export with judge gating."""

from __future__ import annotations

from pathlib import Path

from zeropath.core.evidence import evidence_score, missing_evidence
from zeropath.core.errors import ReportNotReadyError
from zeropath.core.schemas import CandidateFinding, JudgeResult, SourceLocation
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
    fmt = report_format.lower()
    label = _status_label(judge, draft)
    notice = _readiness_notice(judge, draft)
    severity = judge.severity if judge else candidate.severity_guess or "unknown"

    sections = _sections(candidate, judge)
    header = f"""# {label}: {candidate.title}

Format: {report_format}

{notice}
"""

    if fmt == "sherlock":
        body = _render_sherlock(severity, sections)
    elif fmt == "cantina":
        body = _render_cantina(severity, sections)
    elif fmt == "internal":
        body = _render_internal(severity, sections)
    else:
        body = _render_code4rena(severity, sections)
    return f"{header}\n{body}\n"


def _status_label(judge: JudgeResult | None, draft: bool) -> str:
    ready = bool(judge and judge.report_ready)
    if draft and not ready:
        return "DRAFT / NOT READY FOR SUBMISSION"
    if draft:
        return "DRAFT / JUDGE PASSED"
    if ready:
        return "FINAL / REPORT READY"
    return "FINAL REQUESTED / JUDGE NOT READY"


def _readiness_notice(judge: JudgeResult | None, draft: bool) -> str:
    ready = bool(judge and judge.report_ready)
    if draft and not ready:
        return (
            "> DRAFT / NOT READY: this report has not passed the judge gate and "
            "must not be submitted as a final finding."
        )
    if draft:
        return "> DRAFT: the judge gate passed, but this artifact was exported as a draft."
    if ready:
        return "> FINAL / REPORT READY: the judge gate passed for final export."
    return (
        "> NOT READY: the judge gate has not passed. Final exports are refused by "
        "`export_report`."
    )


def _sections(candidate: CandidateFinding, judge: JudgeResult | None) -> dict[str, str]:
    return {
        "evidence_gate": _render_evidence_gate(candidate, judge),
        "links": _render_links(candidate),
        "details": _render_details(candidate),
        "impact": _render_impact(candidate),
        "poc": _render_poc(candidate),
        "mitigation": _render_mitigation(candidate),
        "evidence": _render_evidence_summary(candidate),
        "rejection": _render_rejection_checks(candidate),
        "judge_status": _render_judge_status(judge),
        "judge_blockers": _render_judge_blockers(judge),
        "judge_next_steps": _render_judge_next_steps(judge),
    }


def _render_code4rena(severity: str, sections: dict[str, str]) -> str:
    return _join_sections(
        ("Evidence Gate", sections["evidence_gate"]),
        ("Severity", severity),
        ("Links To Affected Code", sections["links"]),
        ("Vulnerability Details", sections["details"]),
        ("Impact", sections["impact"]),
        ("Proof Of Concept", sections["poc"]),
        ("Recommended Mitigation", sections["mitigation"]),
        ("Evidence Summary", sections["evidence"]),
        ("Rejection Checks", sections["rejection"]),
        ("Judge Status", sections["judge_status"]),
        ("Judge Blockers", sections["judge_blockers"]),
        ("Judge Required Next Steps", sections["judge_next_steps"]),
    )


def _render_sherlock(severity: str, sections: dict[str, str]) -> str:
    return _join_sections(
        ("Evidence Gate", f"Severity: {severity}\n\n{sections['evidence_gate']}"),
        ("Summary", sections["details"]),
        ("Vulnerability Detail", sections["links"]),
        ("Impact", sections["impact"]),
        ("Code Snippet", sections["links"]),
        ("Tool used", "ZeroPath evidence-first workflow."),
        ("Recommendation", sections["mitigation"]),
        ("Evidence Summary", sections["evidence"]),
        ("Rejection Checks", sections["rejection"]),
        ("Judge Status", sections["judge_status"]),
        ("Judge Blockers", sections["judge_blockers"]),
        ("Judge Required Next Steps", sections["judge_next_steps"]),
    )


def _render_cantina(severity: str, sections: dict[str, str]) -> str:
    return _join_sections(
        ("Evidence Gate", f"Severity: {severity}\n\n{sections['evidence_gate']}"),
        ("Description", sections["details"]),
        ("Impact", sections["impact"]),
        ("Proof of Concept", sections["poc"]),
        ("Affected Code", sections["links"]),
        ("Recommendation", sections["mitigation"]),
        (
            "Evidence and Judge Checks",
            "\n\n".join([sections["evidence"], sections["rejection"]]),
        ),
        ("Judge Status", sections["judge_status"]),
        ("Judge Blockers", sections["judge_blockers"]),
        ("Judge Required Next Steps", sections["judge_next_steps"]),
    )


def _render_internal(severity: str, sections: dict[str, str]) -> str:
    return _join_sections(
        ("Evidence Gate", sections["evidence_gate"]),
        ("Judge Status", sections["judge_status"]),
        ("Judge Blockers", sections["judge_blockers"]),
        ("Judge Required Next Steps", sections["judge_next_steps"]),
        ("Severity", severity),
        ("Root Cause", sections["links"]),
        ("Exploit Path", sections["details"]),
        ("Impact", sections["impact"]),
        ("PoC", sections["poc"]),
        ("Mitigation", sections["mitigation"]),
        ("Evidence Summary", sections["evidence"]),
        ("Rejection Checks", sections["rejection"]),
    )


def _join_sections(*sections: tuple[str, str]) -> str:
    return "\n\n".join(f"## {title}\n\n{content}" for title, content in sections)


def _render_evidence_gate(candidate: CandidateFinding, judge: JudgeResult | None) -> str:
    evidence = candidate.evidence
    missing = missing_evidence(evidence)
    verdict = "REPORT READY" if judge and judge.report_ready else "NOT READY"
    explanation = judge.explanation if judge and judge.explanation else "Judge has not run."
    proof_status = _proof_status(candidate)
    live_context = _live_context(candidate)
    return "\n".join(
        [
            f"- Judge verdict: {verdict}",
            f"- Judge explanation: {explanation}",
            f"- Evidence score: {evidence_score(evidence)}",
            f"- Missing evidence: {', '.join(missing) if missing else 'None'}",
            f"- Proof status: {proof_status}",
            f"- Live context: {live_context}",
        ]
    )


def _render_links(candidate: CandidateFinding) -> str:
    if not candidate.root_cause_locations:
        return "- NOT READY: no affected source location has been recorded."
    return "\n".join(_format_location(loc) for loc in candidate.root_cause_locations)


def _render_details(candidate: CandidateFinding) -> str:
    claim = candidate.notes or "NOT READY: write the evidence-backed exploit claim."
    lines = [
        f"**Claim:** {claim}",
        f"**Affected invariant:** {candidate.affected_invariant or 'not recorded'}",
        f"**Bug class:** {candidate.bug_class or 'not recorded'}",
        (
            "**Attacker model:** "
            f"{candidate.attacker_model or 'NOT READY: untrusted attacker model missing'}"
        ),
        "",
        "**Affected contracts:**",
        _bullets(candidate.affected_contracts, empty="- Not recorded."),
        "",
        "**Entrypoints:**",
        _bullets(candidate.entrypoints, empty="- Not recorded."),
        "",
        "**Required state:**",
        _bullets(
            candidate.required_state,
            empty="- NOT READY: reachable state preconditions missing.",
        ),
        "",
        "**Transaction sequence:**",
        _numbered(
            candidate.transaction_sequence,
            empty="NOT READY: attacker transaction path missing.",
        ),
    ]
    return "\n".join(lines)


def _render_impact(candidate: CandidateFinding) -> str:
    impact = candidate.impact
    lines = [
        f"- Impact type: {impact.impact_type}",
        f"- Funds at risk: {_yes_no(impact.funds_at_risk)}",
        f"- Measured: {_yes_no(impact.measured)}",
        f"- Amount: {impact.amount or 'not measured'}",
        f"- Victim: {impact.victim or 'not recorded'}",
    ]
    if impact.explanation:
        lines.extend(["", impact.explanation])
    else:
        lines.extend(["", "NOT READY: add a concrete impact explanation tied to the proof."])
    return "\n".join(lines)


def _render_poc(candidate: CandidateFinding) -> str:
    evidence = candidate.evidence
    poc = _format_artifact(evidence.poc_path) if evidence.poc_path else "not recorded"
    trace = _format_artifact(evidence.trace_path) if evidence.trace_path else "not recorded"
    fork_block = evidence.fork_block if evidence.fork_block is not None else "not checked"
    return "\n".join(
        [
            f"- PoC artifact: {poc}",
            f"- Forge result: {evidence.forge_result or 'not run'}",
            f"- Invariant test result: {evidence.invariant_test_result or 'not run'}",
            f"- Trace artifact: {trace}",
            f"- Chain ID: {evidence.chain_id if evidence.chain_id is not None else 'not checked'}",
            f"- Fork block: {fork_block}",
        ]
    )


def _render_mitigation(candidate: CandidateFinding) -> str:
    invariant = candidate.affected_invariant or candidate.impact.impact_type
    return "\n".join(
        [
            (
                f"- Enforce the affected invariant (`{invariant}`) at the source "
                "locations listed above."
            ),
            (
                "- Add regression coverage for the required state and transaction "
                "sequence in this report."
            ),
            "- Re-run the proof and judge gate after the patch.",
        ]
    )


def _render_evidence_summary(candidate: CandidateFinding) -> str:
    evidence = candidate.evidence
    missing = missing_evidence(evidence)
    rows = [
        (
            "Root cause source lines",
            _yes_no(evidence.root_cause_lines_present),
            _source_count(candidate),
        ),
        (
            "Attacker transaction path",
            _yes_no(evidence.attacker_path_present),
            _count_detail(candidate.transaction_sequence, "step"),
        ),
        (
            "State preconditions",
            _yes_no(evidence.state_preconditions_present),
            _count_detail(candidate.required_state, "precondition"),
        ),
        (
            "Known issue check",
            _yes_no(evidence.known_issues_checked),
            candidate.known_issue_risk or "not recorded",
        ),
        (
            "Duplicate risk check",
            _yes_no(evidence.duplicate_risk_checked),
            candidate.duplicate_risk or "not recorded",
        ),
        ("Live config check", _yes_no(evidence.live_config_checked), _live_context(candidate)),
        ("PoC artifact", _yes_no(bool(evidence.poc_path)), evidence.poc_path or "not recorded"),
        (
            "Trace artifact",
            _yes_no(bool(evidence.trace_path)),
            evidence.trace_path or "not recorded",
        ),
        ("Forge result", evidence.forge_result or "not run", ""),
        ("Invariant test result", evidence.invariant_test_result or "not run", ""),
        (
            "Profit measured",
            _yes_no(evidence.profit_measured),
            candidate.impact.amount or "not measured",
        ),
    ]
    table = ["| Evidence | Status | Detail |", "| --- | --- | --- |"]
    table.extend(
        f"| {_cell(name)} | {_cell(status)} | {_cell(detail)} |"
        for name, status, detail in rows
    )
    notes = _bullets(evidence.notes, empty="- No additional evidence notes recorded.")
    return "\n".join(
        [
            f"Evidence score: {evidence_score(evidence)}",
            "",
            "Missing evidence:",
            _bullets(missing, empty="- None"),
            "",
            *table,
            "",
            "Evidence notes:",
            notes,
        ]
    )


def _render_rejection_checks(candidate: CandidateFinding) -> str:
    if not candidate.rejection_checks:
        return "- No candidate rejection checks recorded."
    lines = []
    for check in candidate.rejection_checks:
        status = "passed" if check.passed else "blocked"
        line = f"- {check.check_name}: {status} - {check.reason}"
        if check.evidence:
            line += f" Evidence: {check.evidence}"
        lines.append(line)
    return "\n".join(lines)


def _render_judge_status(judge: JudgeResult | None) -> str:
    if judge is None:
        return "Report ready: False\n\nExplanation: Judge has not run."
    return "\n\n".join(
        [
            f"Report ready: {judge.report_ready}",
            f"Severity: {judge.severity}",
            f"Explanation: {judge.explanation or 'not recorded'}",
        ]
    )


def _render_judge_blockers(judge: JudgeResult | None) -> str:
    if judge is None:
        return "- Judge has not run."
    if judge.blocking_objections:
        return _bullets(judge.blocking_objections)
    if judge.report_ready:
        return "- None"
    return (
        "- No blocking objections recorded, but judge has not marked this candidate "
        "report-ready."
    )


def _render_judge_next_steps(judge: JudgeResult | None) -> str:
    if judge is None:
        return "- Run `zeropath judge` before final reporting."
    if judge.required_next_steps:
        return _bullets(judge.required_next_steps)
    if judge.report_ready:
        return "- None"
    return "- Add evidence, rerun judge, and export final only after the judge gate passes."


def _format_location(loc: SourceLocation) -> str:
    label = _location_label(loc)
    target = _source_link_target(loc)
    parts = [_markdown_link(label, target)]
    scope = _location_scope(loc)
    if scope:
        parts.append(f"`{scope}`")
    if loc.description:
        parts.append(loc.description)
    return "- " + " - ".join(parts)


def _location_label(loc: SourceLocation) -> str:
    if loc.line_start and loc.line_end and loc.line_end != loc.line_start:
        return f"{loc.file}:{loc.line_start}-{loc.line_end}"
    if loc.line_start:
        return f"{loc.file}:{loc.line_start}"
    return loc.file


def _source_link_target(loc: SourceLocation) -> str:
    target = loc.file
    if loc.line_start and loc.line_end and loc.line_end != loc.line_start:
        return f"{target}#L{loc.line_start}-L{loc.line_end}"
    if loc.line_start:
        return f"{target}#L{loc.line_start}"
    return target


def _location_scope(loc: SourceLocation) -> str:
    if loc.contract and loc.function:
        return f"{loc.contract}.{loc.function}"
    return loc.contract or loc.function or ""


def _format_artifact(path: str) -> str:
    return _markdown_link(path, path)


def _markdown_link(label: str, target: str) -> str:
    wrapped_target = f"<{target}>" if any(char.isspace() for char in target) else target
    return f"[`{label}`]({wrapped_target})"


def _proof_status(candidate: CandidateFinding) -> str:
    evidence = candidate.evidence
    if evidence.forge_result == "passed" or evidence.invariant_test_result == "passed":
        return "passing proof recorded"
    if evidence.poc_path or evidence.trace_path:
        return "artifact recorded but no passing proof result"
    return "not recorded"


def _live_context(candidate: CandidateFinding) -> str:
    evidence = candidate.evidence
    details = []
    if evidence.chain_id is not None:
        details.append(f"chain {evidence.chain_id}")
    if evidence.fork_block is not None:
        details.append(f"fork block {evidence.fork_block}")
    if evidence.live_config_checked:
        details.append("live config checked")
    return ", ".join(details) if details else "not checked"


def _source_count(candidate: CandidateFinding) -> str:
    return _count_detail(candidate.root_cause_locations, "location")


def _count_detail(items: list[object], singular: str) -> str:
    count = len(items)
    plural = singular if count == 1 else f"{singular}s"
    return f"{count} {plural}"


def _numbered(items: list[str], *, empty: str) -> str:
    return "\n".join(f"{idx + 1}. {item}" for idx, item in enumerate(items)) if items else empty


def _bullets(items: list[str], *, empty: str = "- None") -> str:
    return "\n".join(f"- {item}" for item in items) if items else empty


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")
