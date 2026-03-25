"""
Command-line interface for ZeroPath.

Commands:
  analyze       Analyze contracts from a local path or GitHub URL.
  diff          Compare two versions of a protocol.
  import-graph  Load a saved JSON graph into Neo4j.
  query         Interactive Cypher query shell against Neo4j.

GitHub URL formats accepted:
  https://github.com/owner/repo
  https://github.com/owner/repo/tree/branch
  https://github.com/owner/repo/tree/branch/path/to/contracts
  owner/repo  (shorthand)
"""

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from zeropath.config import Settings
from zeropath.exceptions import GitHubIngestionError, ZeropathError
from zeropath.graph_builder import ProtocolGraphBuilder
from zeropath.graph_db import Neo4jGraphDB
from zeropath.logging_config import configure_logging, get_logger
from zeropath.models import ProtocolGraph

logger = get_logger(__name__)
console = Console()

_GITHUB_URL_RE = re.compile(
    r"(?:https?://github\.com/)?(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)"
    r"(?:/tree/(?P<branch>[^/]+)(?P<subpath>/.*)?)?"
)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.option("--log-level", default="INFO", show_default=True, help="Logging level.")
@click.option("--log-file", type=Path, default=None, help="Write logs to file.")
@click.pass_context
def cli(ctx: click.Context, log_level: str, log_file: Optional[Path]) -> None:
    """ZeroPath — production-grade smart contract protocol analyzer."""
    configure_logging(log_level=log_level, log_file=log_file)
    ctx.ensure_object(dict)
    ctx.obj["settings"] = Settings()


# ---------------------------------------------------------------------------
# analyze command
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("source")
@click.option(
    "--output", "-o",
    type=Path,
    default=Path("output/graph.json"),
    show_default=True,
    help="Output JSON file path.",
)
@click.option("--no-storage", is_flag=True, help="Skip storage layout extraction.")
@click.option("--no-flows", is_flag=True, help="Skip asset flow extraction.")
@click.option("--no-proxies", is_flag=True, help="Skip proxy detection.")
@click.option("--solc", default=None, help="Pin solc version (e.g. 0.8.19).")
@click.option("--workers", default=None, type=int, help="Parallel worker count.")
@click.option("--neo4j-uri", default=None, help="Neo4j URI.")
@click.option("--neo4j-user", default=None, help="Neo4j username.")
@click.option("--neo4j-password", default=None, help="Neo4j password.")
@click.option("--store-graph", is_flag=True, help="Store graph in Neo4j after analysis.")
@click.option("--clear-db", is_flag=True, help="Clear Neo4j database before storing.")
@click.pass_context
def analyze(
    ctx: click.Context,
    source: str,
    output: Path,
    no_storage: bool,
    no_flows: bool,
    no_proxies: bool,
    solc: Optional[str],
    workers: Optional[int],
    neo4j_uri: Optional[str],
    neo4j_user: Optional[str],
    neo4j_password: Optional[str],
    store_graph: bool,
    clear_db: bool,
) -> None:
    """
    Analyze smart contracts and build a protocol graph.

    SOURCE can be:
      - A local .sol or .vy file
      - A local directory containing contracts
      - A GitHub URL: https://github.com/owner/repo[/tree/branch[/path]]
      - GitHub shorthand: owner/repo
    """
    settings: Settings = ctx.obj["settings"]
    tmp_dir: Optional[Path] = None

    try:
        # --- Resolve source to a local path ---
        contract_path = _resolve_source(source, settings)

        builder = ProtocolGraphBuilder(
            solc_version=solc,
            extract_storage=not no_storage,
            extract_flows=not no_flows,
            detect_proxies=not no_proxies,
            max_workers=workers,
        )

        with console.status("[bold green]Building protocol graph…"):
            if contract_path.is_file():
                graph = builder.build_from_files([contract_path])
            else:
                graph = builder.build_from_directory(contract_path)

        # --- Save JSON ---
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w", encoding="utf-8") as f:
            json.dump(graph.model_dump(by_alias=True), f, indent=2, default=str)
        console.print(f"[green]✓[/green] Graph saved → {output}")

        # --- Rich summary ---
        _display_graph_summary(graph)

        # --- Neo4j ---
        if store_graph:
            uri = neo4j_uri or settings.neo4j_uri
            user = neo4j_user or settings.neo4j_username
            pw = neo4j_password or settings.neo4j_password
            _store_in_neo4j(graph, uri, user, pw, clear_db)

    except ZeropathError as exc:
        console.print(f"[red]✗ Analysis failed:[/red] {exc}")
        raise click.Exit(1)
    except Exception as exc:
        console.print(f"[red]✗ Unexpected error:[/red] {exc}")
        logger.exception("unexpected_cli_error")
        raise click.Exit(1)
    finally:
        if tmp_dir and tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# diff command
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("source_v1")
@click.argument("source_v2")
@click.option("--output", "-o", type=Path, default=Path("output/diff.json"), show_default=True)
@click.option("--solc", default=None)
@click.pass_context
def diff(
    ctx: click.Context,
    source_v1: str,
    source_v2: str,
    output: Path,
    solc: Optional[str],
) -> None:
    """
    Compare two protocol versions and produce a diff graph.

    SOURCE_V1 and SOURCE_V2 accept the same formats as the analyze command.
    """
    settings: Settings = ctx.obj["settings"]
    try:
        path_v1 = _resolve_source(source_v1, settings)
        path_v2 = _resolve_source(source_v2, settings)

        builder = ProtocolGraphBuilder(solc_version=solc)

        def _collect_files(p: Path) -> list[Path]:
            if p.is_file():
                return [p]
            return [f for f in p.rglob("*") if f.suffix in (".sol", ".vy")]

        with console.status("[bold green]Running version diff analysis…"):
            graph = builder.build_version_diff(
                _collect_files(path_v1),
                _collect_files(path_v2),
            )

        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w", encoding="utf-8") as f:
            json.dump(graph.model_dump(by_alias=True), f, indent=2, default=str)
        console.print(f"[green]✓[/green] Diff saved → {output}")

        if graph.version_diff:
            vd = graph.version_diff
            table = Table(title="Version Diff", show_header=True)
            table.add_column("Category", style="cyan")
            table.add_column("Items", style="white")
            table.add_row("Added contracts", ", ".join(vd.added_contracts) or "—")
            table.add_row("Removed contracts", ", ".join(vd.removed_contracts) or "—")
            table.add_row("Added functions", str(len(vd.added_functions)))
            table.add_row("Removed functions", str(len(vd.removed_functions)))
            table.add_row("Modified functions", str(len(vd.modified_functions)))
            table.add_row("New external deps", ", ".join(vd.new_external_deps) or "—")
            delta_color = {
                "minimal": "green",
                "low": "yellow",
                "medium": "orange3",
                "high": "red",
            }.get(vd.attack_surface_delta, "white")
            table.add_row(
                "Attack surface delta",
                Text(vd.attack_surface_delta.upper(), style=delta_color),
            )
            console.print(table)

    except ZeropathError as exc:
        console.print(f"[red]✗ Diff failed:[/red] {exc}")
        raise click.Exit(1)


# ---------------------------------------------------------------------------
# import-graph command
# ---------------------------------------------------------------------------


@cli.command("import-graph")
@click.argument("graph_file", type=Path)
@click.option("--neo4j-uri", default=None)
@click.option("--neo4j-user", default=None)
@click.option("--neo4j-password", default=None)
@click.option("--clear-db", is_flag=True)
@click.pass_context
def import_graph(
    ctx: click.Context,
    graph_file: Path,
    neo4j_uri: Optional[str],
    neo4j_user: Optional[str],
    neo4j_password: Optional[str],
    clear_db: bool,
) -> None:
    """Load a saved protocol graph JSON into Neo4j."""
    settings: Settings = ctx.obj["settings"]
    try:
        with open(graph_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        graph = ProtocolGraph.model_validate(data)
        _store_in_neo4j(
            graph,
            neo4j_uri or settings.neo4j_uri,
            neo4j_user or settings.neo4j_username,
            neo4j_password or settings.neo4j_password,
            clear_db,
        )
    except Exception as exc:
        console.print(f"[red]✗ Import failed:[/red] {exc}")
        raise click.Exit(1)


# ---------------------------------------------------------------------------
# query command
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--neo4j-uri", default=None)
@click.option("--neo4j-user", default=None)
@click.option("--neo4j-password", default=None)
@click.pass_context
def query(
    ctx: click.Context,
    neo4j_uri: Optional[str],
    neo4j_user: Optional[str],
    neo4j_password: Optional[str],
) -> None:
    """Interactive Cypher query shell against Neo4j."""
    settings: Settings = ctx.obj["settings"]
    db = Neo4jGraphDB(
        uri=neo4j_uri or settings.neo4j_uri,
        username=neo4j_user or settings.neo4j_username,
        password=neo4j_password or settings.neo4j_password,
    )
    try:
        db.connect()
    except Exception as exc:
        console.print(f"[red]✗ Neo4j connection failed:[/red] {exc}")
        raise click.Exit(1)

    console.print(Panel("[bold]ZeroPath Neo4j Query Shell[/bold]\nType [cyan]help[/cyan] or [cyan]exit[/cyan]."))

    try:
        while True:
            try:
                cmd = console.input("[cyan]zeropath>[/cyan] ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not cmd:
                continue
            if cmd in ("exit", "quit", "\\q"):
                break
            if cmd == "help":
                _print_query_help()
                continue

            # Built-in shortcuts
            if cmd.startswith("calls "):
                results = db.get_contract_call_graph(cmd[6:].strip())
            elif cmd.startswith("externals "):
                results = db.get_external_calls(cmd[10:].strip())
            elif cmd.startswith("flows "):
                paths = db.get_asset_flow_paths(cmd[6:].strip())
                for p in paths:
                    console.print(" → ".join(p))
                continue
            elif cmd == "proxies":
                results = db.get_proxy_contracts()
            elif cmd == "payable":
                results = db.get_payable_functions()
            elif cmd == "reentrancy":
                results = db.find_reentrancy_candidates()
            else:
                try:
                    results = db.query(cmd)
                except Exception as exc:
                    console.print(f"[red]Query error:[/red] {exc}")
                    continue

            _display_query_results(results)
    finally:
        db.disconnect()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_source(source: str, settings: Settings) -> Path:
    """
    Resolve SOURCE (local path or GitHub URL/shorthand) to a local Path.

    For GitHub inputs, clones the repo into a temp directory and returns
    the path to the contracts subdirectory (if specified in the URL).
    """
    # Already a local path?
    local = Path(source)
    if local.exists():
        return local.resolve()

    # GitHub?
    m = _GITHUB_URL_RE.match(source)
    if m:
        return _clone_github(
            owner=m.group("owner"),
            repo=m.group("repo"),
            branch=m.group("branch"),
            subpath=m.group("subpath"),
            settings=settings,
        )

    raise click.BadParameter(
        f"'{source}' is neither a valid local path nor a recognised GitHub URL."
    )


def _clone_github(
    owner: str,
    repo: str,
    branch: Optional[str],
    subpath: Optional[str],
    settings: Settings,
) -> Path:
    """Clone a GitHub repo into a temp directory and return the contracts path."""
    repo_url = f"https://github.com/{owner}/{repo}.git"

    if settings.github_token:
        repo_url = f"https://{settings.github_token}@github.com/{owner}/{repo}.git"

    clone_root = settings.github_clone_dir / f"{owner}_{repo}"
    clone_root.parent.mkdir(parents=True, exist_ok=True)

    logger.info("cloning_github_repo", url=repo_url, dest=str(clone_root))
    console.print(f"[bold]Cloning[/bold] {owner}/{repo}…")

    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [repo_url, str(clone_root)]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise GitHubIngestionError(
                f"git clone failed:\n{result.stderr.strip()}"
            )
    except FileNotFoundError:
        raise GitHubIngestionError(
            "git is not installed or not on PATH. Cannot clone GitHub repos."
        )
    except subprocess.TimeoutExpired:
        raise GitHubIngestionError(f"git clone timed out after 120 s for {repo_url}")

    # Resolve subpath if present
    contracts_dir = clone_root
    if subpath:
        contracts_dir = clone_root / subpath.lstrip("/")

    if not contracts_dir.exists():
        raise GitHubIngestionError(
            f"Subpath '{subpath}' not found in cloned repo at {clone_root}"
        )

    console.print(f"[green]✓[/green] Cloned to {clone_root}")
    return contracts_dir


def _store_in_neo4j(
    graph: ProtocolGraph,
    uri: str,
    username: str,
    password: str,
    clear_first: bool = False,
) -> None:
    with console.status("[bold green]Connecting to Neo4j…"):
        db = Neo4jGraphDB(uri=uri, username=username, password=password)
        db.connect()
    try:
        with console.status("[bold green]Storing graph in Neo4j…"):
            db.store_protocol_graph(graph, clear_first=clear_first)
        console.print("[green]✓[/green] Graph stored in Neo4j")
    finally:
        db.disconnect()


def _display_graph_summary(graph: ProtocolGraph) -> None:
    table = Table(title="Protocol Graph Summary", show_lines=True)
    table.add_column("Component", style="cyan", min_width=22)
    table.add_column("Count", style="bold magenta", justify="right")
    table.add_column("Detail", style="dim")

    table.add_row("Contracts", str(len(graph.contracts)),
                  ", ".join(c.name for c in graph.contracts[:5]))
    table.add_row("Functions", str(len(graph.functions)), "")
    table.add_row("State variables", str(len(graph.state_variables)), "")
    table.add_row("Events", str(len(graph.events)), "")
    table.add_row("Call edges", str(len(graph.function_calls)), "")
    table.add_row("Asset flows", str(len(graph.asset_flows)), "")
    table.add_row("External deps", str(len(graph.external_dependencies)),
                  ", ".join(d.name for d in graph.external_dependencies[:5]))
    table.add_row("Proxy relationships", str(len(graph.proxy_relationships)), "")

    proxies = [c for c in graph.contracts if c.proxy_type.value != "none"]
    if proxies:
        table.add_row(
            "Proxy contracts",
            str(len(proxies)),
            ", ".join(f"{c.name} ({c.proxy_type.value})" for c in proxies),
        )

    console.print(table)

    if graph.version_diff:
        console.print(
            Panel(
                f"[bold]Version diff:[/bold] attack surface delta = "
                f"[yellow]{graph.version_diff.attack_surface_delta.upper()}[/yellow]",
                expand=False,
            )
        )


def _print_query_help() -> None:
    console.print(
        Panel(
            "[bold]Built-in shortcuts:[/bold]\n"
            "  [cyan]calls <ContractName>[/cyan]     — call graph for a contract\n"
            "  [cyan]externals <FunctionName>[/cyan] — external calls from a function\n"
            "  [cyan]flows <FunctionName>[/cyan]     — asset flow paths from a function\n"
            "  [cyan]proxies[/cyan]                  — list all proxy contracts\n"
            "  [cyan]payable[/cyan]                  — list all payable functions\n"
            "  [cyan]reentrancy[/cyan]               — reentrancy candidates\n"
            "  [cyan]<Cypher query>[/cyan]           — execute raw Cypher\n"
            "  [cyan]exit[/cyan]                     — quit",
            title="Help",
            expand=False,
        )
    )


def _display_query_results(results: list[dict]) -> None:
    if not results:
        console.print("[yellow]No results.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold cyan")
    for key in results[0]:
        table.add_column(key)
    for row in results:
        table.add_row(*[str(v) for v in row.values()])
    console.print(table)


def main() -> None:
    """Entry point registered in pyproject.toml."""
    cli(obj={})


if __name__ == "__main__":
    main()
