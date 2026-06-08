"""`zeropath candidates` command surface."""

import json
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

if not hasattr(click, "Exit"):
    click.Exit = click.exceptions.Exit

console = Console()


@click.group("candidates")
def candidates() -> None:
    """List, inspect, and update candidate hypotheses."""


@candidates.command("list")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def candidates_list(repo: Path) -> None:
    from zeropath.core.evidence import evidence_score
    from zeropath.core.storage import Storage

    storage = Storage(repo)
    candidate_items = storage.list_candidates()
    table = Table(title="ZeroPath candidates", show_header=True)
    table.add_column("ID"); table.add_column("Status"); table.add_column("Evidence"); table.add_column("Title")
    for candidate in candidate_items:
        table.add_row(candidate.id, candidate.status, str(evidence_score(candidate.evidence)), candidate.title)
    if not candidate_items:
        table.add_row("-", "-", "-", "No candidates yet.")
    console.print(table)


@candidates.command("show")
@click.argument("candidate_id")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def candidates_show(candidate_id: str, repo: Path) -> None:
    from zeropath.core.storage import Storage

    candidate = Storage(repo).load_candidate(candidate_id)
    if candidate is None:
        console.print(f"[red]Candidate not found:[/red] {candidate_id}")
        raise click.Exit(1)
    console.print_json(json.dumps(candidate.model_dump(mode="json"), indent=2))


@candidates.command("update")
@click.argument("candidate_id")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--status", required=True, type=click.Choice([
    "observation", "hypothesis", "path_identified", "state_planned", "poc_generated",
    "poc_passed", "judge_passed", "report_ready", "rejected", "stale", "needs_evidence",
]))
@click.option("--reason", default=None, help="Evidence or rejection reason.")
def candidates_update(candidate_id: str, repo: Path, status: str, reason: Optional[str]) -> None:
    from zeropath.core.storage import Storage

    try:
        candidate = Storage(repo).update_candidate_status(candidate_id, status, reason)
    except Exception as exc:
        console.print(f"[red]Update failed:[/red] {exc}")
        raise click.Exit(1)
    console.print(f"[green]{candidate.id}[/green] -> {candidate.status}")


@candidates.command("evidence")
@click.argument("candidate_id")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--root-cause-lines", is_flag=True, help="Mark root cause source lines as evidenced.")
@click.option("--attacker-path", is_flag=True, help="Mark attacker transaction path as evidenced.")
@click.option("--state-preconditions", is_flag=True, help="Mark reachable state preconditions as evidenced.")
@click.option("--known-issues-checked", is_flag=True, help="Mark known-issue triage as complete.")
@click.option("--duplicate-risk-checked", is_flag=True, help="Mark duplicate-risk triage as complete.")
@click.option("--live-config-checked", is_flag=True, help="Mark deployment/fork configuration as checked.")
@click.option("--duplicate-risk", type=click.Choice(["none", "low", "medium", "high"], case_sensitive=False))
@click.option("--known-issue-risk", type=click.Choice(["none", "low", "medium", "high"], case_sensitive=False))
@click.option("--chain-id", type=int)
@click.option("--fork-block", type=int)
@click.option("--poc-path", type=click.Path(path_type=Path))
@click.option("--trace-path", type=click.Path(path_type=Path))
@click.option("--forge-result", type=click.Choice(["passed", "failed", "unavailable", "not_run"], case_sensitive=False))
@click.option("--invariant-test-result", type=click.Choice(["passed", "failed", "unavailable", "not_run"], case_sensitive=False))
@click.option("--impact-measured", is_flag=True)
@click.option("--profit-measured", is_flag=True)
@click.option("--amount", default=None, help="Concrete measured impact amount or bound.")
@click.option("--note", "notes", multiple=True, help="Append an evidence note. Repeatable.")
def candidates_evidence(
    candidate_id: str,
    repo: Path,
    root_cause_lines: bool,
    attacker_path: bool,
    state_preconditions: bool,
    known_issues_checked: bool,
    duplicate_risk_checked: bool,
    live_config_checked: bool,
    duplicate_risk: Optional[str],
    known_issue_risk: Optional[str],
    chain_id: Optional[int],
    fork_block: Optional[int],
    poc_path: Optional[Path],
    trace_path: Optional[Path],
    forge_result: Optional[str],
    invariant_test_result: Optional[str],
    impact_measured: bool,
    profit_measured: bool,
    amount: Optional[str],
    notes: tuple[str, ...],
) -> None:
    """Record concrete evidence and triage facts for a candidate."""
    from zeropath.core.candidates import update_candidate_evidence
    from zeropath.core.evidence import evidence_score, missing_evidence
    from zeropath.core.storage import Storage

    try:
        candidate = update_candidate_evidence(
            Storage(repo),
            candidate_id,
            root_cause_lines_present=root_cause_lines,
            attacker_path_present=attacker_path,
            state_preconditions_present=state_preconditions,
            known_issues_checked=known_issues_checked,
            duplicate_risk_checked=duplicate_risk_checked,
            live_config_checked=live_config_checked,
            duplicate_risk=duplicate_risk,
            known_issue_risk=known_issue_risk,
            chain_id=chain_id,
            fork_block=fork_block,
            poc_path=poc_path,
            trace_path=trace_path,
            forge_result=forge_result,
            invariant_test_result=invariant_test_result,
            impact_measured=impact_measured,
            profit_measured=profit_measured,
            amount=amount,
            notes=list(notes),
        )
    except Exception as exc:
        console.print(f"[red]Evidence update failed:[/red] {exc}")
        raise click.Exit(1)

    table = Table(title=f"Evidence updated: {candidate.id}", show_header=True)
    table.add_column("Field"); table.add_column("Value")
    table.add_row("score", str(evidence_score(candidate.evidence)))
    table.add_row("status", candidate.status)
    table.add_row("duplicate_risk", candidate.duplicate_risk or "unknown")
    table.add_row("known_issue_risk", candidate.known_issue_risk or "unknown")
    table.add_row("missing", ", ".join(missing_evidence(candidate.evidence)) or "none")
    console.print(table)


@candidates.command("plan")
@click.argument("candidate_id")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def candidates_plan(candidate_id: str, repo: Path) -> None:
    """Build and save a proof-state plan for a candidate."""
    from zeropath.core.state_plan import build_candidate_state_plan
    from zeropath.core.storage import Storage

    try:
        plan = build_candidate_state_plan(Storage(repo), candidate_id)
    except Exception as exc:
        console.print(f"[red]State plan failed:[/red] {exc}")
        raise click.Exit(1)

    table = Table(title=f"State plan: {plan.candidate_id}", show_header=True)
    table.add_column("Field"); table.add_column("Value")
    table.add_row("confidence", plan.confidence)
    table.add_row("setup_steps", str(len(plan.setup_steps)))
    table.add_row("transaction_steps", str(len(plan.transaction_steps)))
    table.add_row("missing_dependencies", str(len(plan.missing_dependencies)))
    table.add_row("evidence_to_collect", str(len(plan.evidence_to_collect)))
    table.add_row("artifact", plan.artifact_path or "not saved")
    console.print(table)

    console.print("[bold]Setup steps[/bold]")
    for step in plan.setup_steps:
        console.print(f"- {step}")
    console.print("[bold]Missing dependencies[/bold]")
    for item in plan.missing_dependencies or ["None"]:
        console.print(f"- {item}")


__all__ = ["candidates"]
