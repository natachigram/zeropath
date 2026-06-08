"""`zeropath hunt` command surface."""

from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

if not hasattr(click, "Exit"):
    click.Exit = click.exceptions.Exit

console = Console()


@click.command("hunt")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--mode", type=click.Choice(["critical", "high-medium", "qa"]), default="critical", show_default=True)
@click.option("--limit", type=int, default=5, show_default=True)
@click.option("--focus", default=None, help="Optional focus term, such as oracle or vault.")
def hunt(repo: Path, mode: str, limit: int, focus: Optional[str]) -> None:
    """Generate evidence-seeking hypotheses, not final findings."""
    from zeropath.core.candidates import generate_candidates
    from zeropath.core.storage import Storage

    storage = Storage(repo)
    try:
        candidates = generate_candidates(storage, mode=mode, limit=limit, focus=focus)
    except Exception as exc:
        console.print(f"[red]Hunt failed:[/red] {exc}")
        raise click.Exit(1)
    table = Table(title="Candidate hypotheses", show_header=True)
    table.add_column("ID"); table.add_column("Severity"); table.add_column("Title"); table.add_column("Status")
    for candidate in candidates:
        table.add_row(candidate.id, candidate.severity_guess or "unknown", candidate.title, candidate.status)
    if not candidates:
        table.add_row("-", "-", "No template matched indexed evidence.", "-")
    console.print(table)
    console.print("[yellow]Hypotheses are not findings. Run `zeropath prove` and `zeropath judge` before reporting.[/yellow]")


__all__ = ["hunt"]
