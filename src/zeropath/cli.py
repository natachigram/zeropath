"""
Command-line interface for the zeropath protocol analyzer.
"""

import json
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from zeropath.config import Settings
from zeropath.exceptions import ZeropathError
from zeropath.graph_builder import ProtocolGraphBuilder
from zeropath.graph_db import Neo4jGraphDB
from zeropath.logging_config import configure_logging, get_logger

logger = get_logger(__name__)
console = Console()


@click.group()
@click.option("--log-level", default="INFO", help="Logging level")
@click.option("--log-file", type=Path, help="Log file path")
@click.pass_context
def cli(ctx: click.Context, log_level: str, log_file: Optional[Path]) -> None:
    """
    Zeropath - Production-grade Solidity contract analyzer.
    
    Builds structured protocol graphs for smart contract security research.
    """
    configure_logging(log_level=log_level, log_file=log_file)
    ctx.ensure_object(dict)
    ctx.obj["settings"] = Settings()


@cli.command()
@click.argument("contract_path", type=Path)
@click.option("--output", "-o", type=Path, default=Path("output/graph.json"),
              help="Output JSON file path")
@click.option("--no-storage", is_flag=True, help="Skip storage layout extraction")
@click.option("--no-flows", is_flag=True, help="Skip asset flow extraction")
@click.option("--neo4j-uri", help="Neo4j URI")
@click.option("--neo4j-user", help="Neo4j username")
@click.option("--neo4j-password", help="Neo4j password")
@click.option("--store-graph", is_flag=True, help="Store graph in Neo4j")
@click.pass_context
def analyze(
    ctx: click.Context,
    contract_path: Path,
    output: Path,
    no_storage: bool,
    no_flows: bool,
    neo4j_uri: Optional[str],
    neo4j_user: Optional[str],
    neo4j_password: Optional[str],
    store_graph: bool,
) -> None:
    """
    Analyze Solidity contract(s) and build protocol graph.
    
    CONTRACT_PATH can be a single .sol file or directory.
    """
    try:
        settings = ctx.obj["settings"]
        
        # Resolve path
        path = contract_path.resolve()
        if not path.exists():
            console.print(f"[red]Error: Path not found: {path}[/red]")
            raise click.Exit(1)
        
        # Initialize graph builder
        builder = ProtocolGraphBuilder(
            extract_storage=not no_storage,
            extract_flows=not no_flows,
        )
        
        with console.status("[bold green]Building protocol graph..."):
            # Build graph
            if path.is_file():
                if not path.suffix == ".sol":
                    console.print("[red]Error: File must be a .sol file[/red]")
                    raise click.Exit(1)
                graph = builder.build_from_files([path])
            else:
                graph = builder.build_from_directory(path)
        
        # Save JSON output
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w") as f:
            json.dump(graph.model_dump(), f, indent=2, default=str)
        console.print(f"[green]✓[/green] Graph saved to {output}")
        
        # Display summary
        _display_graph_summary(graph)
        
        # Store in Neo4j if requested
        if store_graph:
            _store_in_neo4j(
                graph,
                neo4j_uri or settings.neo4j_uri,
                neo4j_user or settings.neo4j_username,
                neo4j_password or settings.neo4j_password,
            )
        
    except ZeropathError as e:
        console.print(f"[red]Analysis failed: {e}[/red]")
        logger.error("analysis_failed", error=str(e))
        raise click.Exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        logger.error("unexpected_error", error=str(e))
        raise click.Exit(1)


@cli.command()
@click.argument("graph_file", type=Path)
@click.option("--neo4j-uri", help="Neo4j URI")
@click.option("--neo4j-user", help="Neo4j username")
@click.option("--neo4j-password", help="Neo4j password")
@click.pass_context
def import_graph(
    ctx: click.Context,
    graph_file: Path,
    neo4j_uri: Optional[str],
    neo4j_user: Optional[str],
    neo4j_password: Optional[str],
) -> None:
    """
    Import a previously saved protocol graph into Neo4j.
    """
    try:
        settings = ctx.obj["settings"]
        
        # Load graph
        with open(graph_file, "r") as f:
            graph_data = json.load(f)
        
        # Store in Neo4j
        _store_in_neo4j(
            graph_data,
            neo4j_uri or settings.neo4j_uri,
            neo4j_user or settings.neo4j_username,
            neo4j_password or settings.neo4j_password,
        )
        
    except Exception as e:
        console.print(f"[red]Import failed: {e}[/red]")
        raise click.Exit(1)


@cli.command()
@click.option("--neo4j-uri", help="Neo4j URI")
@click.option("--neo4j-user", help="Neo4j username")
@click.option("--neo4j-password", help="Neo4j password")
@click.option("--contract", help="Filter by contract name")
@click.pass_context
def query(
    ctx: click.Context,
    neo4j_uri: Optional[str],
    neo4j_user: Optional[str],
    neo4j_password: Optional[str],
    contract: Optional[str],
) -> None:
    """
    Run interactive queries against the stored graph.
    """
    try:
        settings = ctx.obj["settings"]
        
        db = Neo4jGraphDB(
            uri=neo4j_uri or settings.neo4j_uri,
            username=neo4j_user or settings.neo4j_username,
            password=neo4j_password or settings.neo4j_password,
        )
        db.connect()
        
        try:
            console.print("[bold]Graph Database Query Interface[/bold]")
            console.print("Type 'help' for available commands")
            
            while True:
                cmd = console.input("[cyan]query>[/cyan] ").strip()
                
                if not cmd:
                    continue
                elif cmd == "help":
                    _print_query_help()
                elif cmd == "exit":
                    break
                elif cmd.startswith("calls "):
                    contract_name = cmd[6:].strip()
                    results = db.get_contract_call_graph(contract_name)
                    _display_query_results(results)
                elif cmd.startswith("externals "):
                    func_name = cmd[10:].strip()
                    results = db.get_external_calls(func_name)
                    _display_query_results(results)
                else:
                    # Treat as Cypher query
                    results = db.query(cmd)
                    _display_query_results(results)
        finally:
            db.disconnect()
            
    except Exception as e:
        console.print(f"[red]Query failed: {e}[/red]")
        raise click.Exit(1)


def _display_graph_summary(graph) -> None:
    """Display a summary of the protocol graph."""
    table = Table(title="Protocol Graph Summary")
    table.add_column("Component", style="cyan")
    table.add_column("Count", style="magenta")
    
    table.add_row("Contracts", str(len(graph.contracts)))
    table.add_row("Functions", str(len(graph.functions)))
    table.add_row("State Variables", str(len(graph.state_variables)))
    table.add_row("Function Calls", str(len(graph.function_calls)))
    table.add_row("Asset Flows", str(len(graph.asset_flows)))
    
    console.print(table)


def _store_in_neo4j(
    graph,
    uri: str,
    username: str,
    password: str,
) -> None:
    """Store graph in Neo4j."""
    with console.status("[bold green]Connecting to Neo4j..."):
        db = Neo4jGraphDB(uri=uri, username=username, password=password)
        db.connect()
    
    try:
        with console.status("[bold green]Storing graph in Neo4j..."):
            db.store_protocol_graph(graph)
        console.print("[green]✓[/green] Graph stored in Neo4j")
    finally:
        db.disconnect()


def _print_query_help() -> None:
    """Print query help."""
    console.print("""
[bold]Available Commands:[/bold]
  calls <contract>     - Show call graph for contract
  externals <func>     - Show external calls from function
  <cypher-query>       - Execute raw Cypher query
  help                 - Show this help
  exit                 - Exit
    """)


def _display_query_results(results: list[dict]) -> None:
    """Display query results in a table."""
    if not results:
        console.print("[yellow]No results[/yellow]")
        return
    
    table = Table()
    for key in results[0].keys():
        table.add_column(key)
    
    for result in results:
        table.add_row(*[str(v) for v in result.values()])
    
    console.print(table)


def main() -> None:
    """Entry point for the CLI."""
    cli(obj={})


if __name__ == "__main__":
    main()
