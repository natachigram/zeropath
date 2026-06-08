"""`zeropath memory` command surface."""

from pathlib import Path
from typing import Any, Optional

import click
from rich.console import Console
from rich.table import Table

if not hasattr(click, "Exit"):
    click.Exit = click.exceptions.Exit

console = Console()


@click.group("memory")
def memory() -> None:
    """Manage the research ledger."""


@memory.command("search")
@click.argument("query")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--scope", default=None)
@click.option("--type", "memory_type", default=None)
@click.option("--tag", "tags", multiple=True)
def memory_search(query: str, repo: Path, scope: Optional[str], memory_type: Optional[str], tags: tuple[str, ...]) -> None:
    from zeropath.core.memory import search_memory
    from zeropath.core.storage import Storage

    results = search_memory(Storage(repo), query, scope=scope, memory_type=memory_type, tags=list(tags))
    _print_memory_table(results, "Memory search")


@memory.command("list")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--type", "memory_type", default=None)
def memory_list(repo: Path, memory_type: Optional[str]) -> None:
    from zeropath.core.storage import Storage

    items = Storage(repo).list_memory()
    if memory_type:
        items = [item for item in items if item.memory_type == memory_type]
    _print_memory_table(items, "Memory")


@memory.command("add")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--type", "memory_type", required=True)
@click.option("--content", required=True)
@click.option("--scope", default="current_project", show_default=True)
@click.option("--confidence", default="inferred", show_default=True)
@click.option("--source", default="manual", show_default=True)
@click.option("--tag", "tags", multiple=True)
@click.option("--user-approved", is_flag=True, help="Allow durable research_lesson admission.")
def memory_add(
    repo: Path,
    memory_type: str,
    content: str,
    scope: str,
    confidence: str,
    source: str,
    tags: tuple[str, ...],
    user_approved: bool,
) -> None:
    from zeropath.core.memory import propose_memory
    from zeropath.core.storage import Storage

    decision, item = propose_memory(
        Storage(repo),
        content=content,
        memory_type=memory_type,
        scope=scope,
        confidence=confidence,
        source=source,
        tags=list(tags),
        context={"user_approved": user_approved},
    )
    if decision.save and item:
        console.print(f"[green]Saved[/green] {item.id}: {decision.reason}")
    else:
        console.print(f"[yellow]Not saved:[/yellow] {decision.reason}")


@memory.command("forget")
@click.argument("memory_id")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def memory_forget(memory_id: str, repo: Path) -> None:
    from zeropath.core.storage import Storage

    removed = Storage(repo).delete_record("memory", memory_id)
    console.print("[green]forgotten[/green]" if removed else "[yellow]not found[/yellow]")


@memory.command("mark-stale")
@click.argument("memory_id")
@click.option("--reason", required=True)
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def memory_mark_stale(memory_id: str, reason: str, repo: Path) -> None:
    from zeropath.core.memory import mark_memory_stale
    from zeropath.core.storage import Storage

    ok = mark_memory_stale(Storage(repo), memory_id, reason)
    console.print("[green]marked stale[/green]" if ok else "[yellow]not found[/yellow]")


@memory.command("refresh-stale")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def memory_refresh_stale(repo: Path) -> None:
    """Mark anchored memories stale when repo or source anchors changed."""
    from zeropath.core.memory import mark_stale_memories
    from zeropath.core.storage import Storage

    marked = mark_stale_memories(Storage(repo))
    _print_memory_table(marked, "Stale memories refreshed")
    console.print(f"[green]Marked stale:[/green] {len(marked)}")


@memory.command("rejected")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def memory_rejected(repo: Path) -> None:
    from zeropath.core.memory import rejected_memories
    from zeropath.core.storage import Storage

    _print_memory_table(rejected_memories(Storage(repo)), "Rejected hypotheses")


@memory.command("consolidate")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def memory_consolidate(repo: Path) -> None:
    from zeropath.core.storage import Storage

    path = Storage(repo).export_json_files()
    console.print(f"[green]Exported storage snapshot:[/green] {path}")


def _print_memory_table(items: list[Any], title: str) -> None:
    table = Table(title=title, show_header=True)
    table.add_column("ID"); table.add_column("Type"); table.add_column("Scope"); table.add_column("Confidence"); table.add_column("Content")
    for item in items:
        table.add_row(item.id, item.memory_type, item.scope, item.confidence, item.content[:90])
    if not items:
        table.add_row("-", "-", "-", "-", "No memory items.")
    console.print(table)


__all__ = ["memory"]
