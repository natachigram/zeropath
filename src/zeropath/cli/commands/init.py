"""`zeropath init` command surface."""

import shutil
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.command("init")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--write-agent-files", is_flag=True, help="Copy agent integration templates into .zeropath/exports.")
def init(repo: Path, write_agent_files: bool) -> None:
    """Initialize local ZeroPath project state."""
    from zeropath.core.project import init_project

    storage, config, detection = init_project(repo)
    if write_agent_files:
        _copy_agent_templates(storage)
    table = Table(title="ZeroPath init", show_header=True)
    table.add_column("Field"); table.add_column("Value")
    table.add_row("project_id", config.project_id)
    table.add_row("adapter", f"{detection.adapter} ({detection.confidence})")
    table.add_row("build_system", detection.build_system or "unknown")
    table.add_row("state", str(storage.zp_dir))
    table.add_row("next", "zeropath ingest --repo .")
    console.print(table)


def _copy_agent_templates(storage) -> None:
    package_dir = Path(__file__).resolve().parents[2]
    template_dir = package_dir / "templates" / "agent"
    if not template_dir.exists():
        return
    exports = storage.zp_dir / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    for template in template_dir.iterdir():
        if template.is_file():
            target = exports / template.name
            if not target.exists():
                shutil.copyfile(template, target)


__all__ = ["init"]
