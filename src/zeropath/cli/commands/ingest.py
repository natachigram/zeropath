"""`zeropath ingest` command surface."""

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

if not hasattr(click, "Exit"):
    click.Exit = click.exceptions.Exit

console = Console()


@click.command("ingest")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--docs", multiple=True, type=click.Path(path_type=Path), help="Documentation path to associate with the project.")
@click.option("--scope", multiple=True, type=click.Path(path_type=Path), help="Scope file to associate with the project.")
def ingest(repo: Path, docs: tuple[Path, ...], scope: tuple[Path, ...]) -> None:
    """Index project files through the detected adapter."""
    from zeropath.adapters.evm import EVMAdapter
    from zeropath.core.storage import Storage

    storage = Storage(repo)
    try:
        config = storage.load_project_config()
    except Exception as exc:
        console.print(f"[red]Ingest blocked:[/red] {exc}")
        raise click.Exit(1)
    config.docs_paths = [str(path) for path in docs] or config.docs_paths
    config.scope_files = [str(path) for path in scope] or config.scope_files
    if config.adapter != "evm":
        console.print(f"[yellow]No stable ingest adapter for {config.adapter!r} yet.[/yellow]")
        raise click.Exit(1)
    adapter = EVMAdapter(config.root_path)
    index = adapter.ingest_project(config)
    config.source_paths = [item["path"] for item in index.get("files", [])]
    storage.save_project_config(config)
    storage.save_record("ingest", "evm_index", index)
    table = Table(title="ZeroPath ingest", show_header=True)
    table.add_column("Metric"); table.add_column("Value")
    table.add_row("adapter", "evm")
    table.add_row("files", str(len(index.get("files", []))))
    table.add_row("contracts", str(len(index.get("contracts", []))))
    table.add_row("functions", str(len(index.get("functions", []))))
    table.add_row("protocol_type", index.get("protocol_type", "unknown"))
    table.add_row("note", "No vulnerability findings were produced.")
    console.print(table)


__all__ = ["ingest"]
