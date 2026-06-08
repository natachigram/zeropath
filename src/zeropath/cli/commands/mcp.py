"""`zeropath mcp` command surface."""

from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table


@click.group("mcp", invoke_without_command=True)
@click.pass_context
def mcp(ctx: click.Context) -> None:
    """Run ZeroPath as an MCP server / install it into your IDE."""
    if ctx.invoked_subcommand is None:
        from zeropath.mcp_server import build_default_server

        build_default_server(workspace_root=Path(".")).serve_forever()


@mcp.command("serve")
@click.option(
    "--kg-dir",
    type=click.Path(exists=False, file_okay=False, path_type=Path),
    default=None,
    help="Directory holding a Phase 8 kg.json snapshot.",
)
@click.pass_context
def mcp_serve(ctx: click.Context, kg_dir: Optional[Path]) -> None:
    """Run the MCP server over stdio (invoked by your IDE, not directly)."""
    from zeropath.mcp_server import build_default_server

    server = build_default_server(kg_dir=kg_dir, workspace_root=Path("."))
    server.serve_forever()


@mcp.command("install")
@click.option(
    "--client",
    type=click.Choice(
        ["claude-desktop", "claude-code", "cursor", "cline", "continue", "all"],
    ),
    default="all",
    show_default=True,
    help="Which IDE config to update.",
)
@click.option(
    "--python",
    default=None,
    help="Python interpreter the IDE should invoke. Defaults to current.",
)
@click.option(
    "--kg-dir",
    type=click.Path(exists=False, file_okay=False, path_type=Path),
    default=None,
    help="Persist a Phase 8 KG dir into the server config.",
)
@click.option("--dry-run", is_flag=True, help="Show the merged config without writing it.")
@click.pass_context
def mcp_install(
    ctx: click.Context,
    client: str,
    python: Optional[str],
    kg_dir: Optional[Path],
    dry_run: bool,
) -> None:
    """Register the ZeroPath MCP server with one or more IDEs."""
    from zeropath.mcp_server import install_for_all, install_for_client

    kg = str(kg_dir) if kg_dir else None
    if client == "all":
        results = install_for_all(python=python, kg_dir=kg, dry_run=dry_run)
    else:
        results = [
            install_for_client(
                client,
                python=python,
                kg_dir=kg,
                dry_run=dry_run,
            ),
        ]

    console = Console()
    table = Table(title="ZeroPath MCP install", show_header=True)
    table.add_column("Client")
    table.add_column("Path")
    table.add_column("Status")
    for result in results:
        if result.error:
            status = f"[red]error[/red]: {result.error}"
        elif dry_run:
            status = "[yellow]dry-run[/yellow]"
        elif result.already_present:
            status = "[cyan]already present (no change)[/cyan]"
        elif result.written:
            status = "[green]installed[/green]"
        else:
            status = "[red]not written[/red]"
        table.add_row(result.client, str(result.config_path), status)
    console.print(table)
    if not dry_run:
        click.echo(
            "[zeropath] restart your IDE to pick up the new MCP server.",
            err=True,
        )


@mcp.command("uninstall")
@click.option(
    "--client",
    type=click.Choice(
        ["claude-desktop", "claude-code", "cursor", "cline", "continue", "all"],
    ),
    default="all",
    show_default=True,
)
@click.pass_context
def mcp_uninstall(ctx: click.Context, client: str) -> None:
    """Remove the ZeroPath MCP entry from one or all IDE configs."""
    from zeropath.mcp_server import SUPPORTED_CLIENTS, uninstall_for_client

    targets = SUPPORTED_CLIENTS if client == "all" else (client,)
    console = Console()
    table = Table(title="ZeroPath MCP uninstall", show_header=True)
    table.add_column("Client")
    table.add_column("Path")
    table.add_column("Status")
    for target in targets:
        result = uninstall_for_client(target)
        if result.error:
            status = f"[red]error[/red]: {result.error}"
        elif result.written:
            status = "[green]removed[/green]"
        else:
            status = "[yellow]not present[/yellow]"
        table.add_row(target, str(result.config_path), status)
    console.print(table)


@mcp.command("tools")
@click.pass_context
def mcp_tools(ctx: click.Context) -> None:
    """List every tool / resource / prompt exposed by the MCP server."""
    from zeropath.mcp_server import build_default_server

    server = build_default_server(workspace_root=Path("."))
    console = Console()

    table = Table(title="MCP tools", show_header=True)
    table.add_column("Tool")
    table.add_column("Description")
    for name, tool in server.tools.items():
        desc = tool.description.replace("\n", " ")
        table.add_row(name, desc[:120])
    console.print(table)

    resources_table = Table(title="MCP resources", show_header=True)
    resources_table.add_column("URI")
    resources_table.add_column("Description")
    for uri, resource in server.resources.items():
        resources_table.add_row(uri, resource.description[:120])
    console.print(resources_table)

    prompt_table = Table(title="MCP prompts", show_header=True)
    prompt_table.add_column("Name")
    prompt_table.add_column("Description")
    for name, prompt in server.prompts.items():
        prompt_table.add_row(name, prompt.description[:120])
    console.print(prompt_table)

__all__ = ["mcp"]
