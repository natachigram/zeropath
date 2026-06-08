"""`zeropath status` command surface."""

import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

if not hasattr(click, "Exit"):
    click.Exit = click.exceptions.Exit

console = Console()


@click.command("status")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def status(repo: Path) -> None:
    """Show current evidence-first project status."""
    from zeropath.core.storage import Storage

    storage = Storage(repo)
    try:
        summary = storage.status_summary()
    except Exception as exc:
        console.print(f"[red]Status unavailable:[/red] {exc}")
        raise click.Exit(1)
    table = Table(title="ZeroPath status", show_header=True)
    table.add_column("Field"); table.add_column("Value")
    for key in ("project_id", "adapter", "build_system", "indexed_contracts", "protocol_intent", "protocol_type", "memory_count"):
        table.add_row(key, str(summary.get(key)))
    table.add_row("candidates", json.dumps(summary.get("candidates_by_status", {}), sort_keys=True))
    if summary.get("last_judge"):
        table.add_row("last_judge", summary["last_judge"]["candidate_id"])
    console.print(table)


__all__ = ["status"]
