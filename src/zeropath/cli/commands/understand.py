"""`zeropath understand` command surface."""

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

if not hasattr(click, "Exit"):
    click.Exit = click.exceptions.Exit

console = Console()


@click.command("understand")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def understand(repo: Path) -> None:
    """Generate a protocol intent snapshot from indexed evidence."""
    from zeropath.core.intent import build_protocol_intent
    from zeropath.core.storage import Storage

    storage = Storage(repo)
    try:
        intent = build_protocol_intent(storage)
    except Exception as exc:
        console.print(f"[red]Understand failed:[/red] {exc}")
        raise click.Exit(1)
    table = Table(title="Protocol intent", show_header=True)
    table.add_column("Field"); table.add_column("Value")
    table.add_row("protocol", intent.protocol_name or "unknown")
    table.add_row("type", intent.protocol_type or "unknown")
    table.add_row("roles", str(len(intent.roles)))
    table.add_row("dependencies", str(len(intent.external_dependencies)))
    table.add_row("invariants", str(len(intent.critical_invariants)))
    table.add_row("snapshot", str(storage.zp_dir / "artifacts/snapshots/protocol_intent.json"))
    console.print(table)
    console.print(intent.summary)


__all__ = ["understand"]
