"""`zeropath report` command surface."""

from pathlib import Path

import click
from rich.console import Console

if not hasattr(click, "Exit"):
    click.Exit = click.exceptions.Exit

console = Console()


@click.command("report")
@click.argument("candidate_id")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--format", "report_format", type=click.Choice(["code4rena", "sherlock", "cantina", "internal"]), default="code4rena", show_default=True)
@click.option("--draft", is_flag=True, help="Export a clearly marked draft even if judge has not passed.")
def report(candidate_id: str, repo: Path, report_format: str, draft: bool) -> None:
    """Export a judge-gated report."""
    from zeropath.core.errors import ReportNotReadyError
    from zeropath.core.reports import export_report
    from zeropath.core.storage import Storage

    try:
        path = export_report(Storage(repo), candidate_id, report_format=report_format, draft=draft)
    except ReportNotReadyError as exc:
        console.print(f"[red]Report refused:[/red] {exc}")
        console.print("Use --draft for an explicitly marked draft, or add evidence and rerun judge.")
        raise click.Exit(1)
    except Exception as exc:
        console.print(f"[red]Report failed:[/red] {exc}")
        raise click.Exit(1)
    console.print(f"[green]Report exported:[/green] {path}")


__all__ = ["report"]
