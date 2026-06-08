"""`zeropath judge` command surface."""

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

if not hasattr(click, "Exit"):
    click.Exit = click.exceptions.Exit

console = Console()


@click.command("judge")
@click.argument("candidate_id")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def judge(candidate_id: str, repo: Path) -> None:
    """Run skeptical judge checks for one candidate."""
    from zeropath.core.judge import judge_candidate
    from zeropath.core.storage import Storage

    storage = Storage(repo)
    candidate = storage.load_candidate(candidate_id)
    if candidate is None:
        console.print(f"[red]Candidate not found:[/red] {candidate_id}")
        raise click.Exit(1)
    result = judge_candidate(candidate, storage)
    table = Table(title=f"Judge {candidate_id}", show_header=True)
    table.add_column("Check"); table.add_column("Value")
    table.add_row("report_ready", str(result.report_ready))
    table.add_row("severity", result.severity)
    table.add_row("funds_at_risk", str(result.funds_at_risk))
    table.add_row("attacker_realistic", str(result.attacker_realistic))
    table.add_row("state_reachable", str(result.state_reachable))
    table.add_row("live_config_reachable", str(result.live_config_reachable))
    table.add_row("blocking", "; ".join(result.blocking_objections) or "none")
    console.print(table)
    if result.required_next_steps:
        console.print("[yellow]Next evidence steps:[/yellow]")
        for step in result.required_next_steps:
            console.print(f"- {step}")


__all__ = ["judge"]
