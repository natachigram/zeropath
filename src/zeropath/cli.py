"""
Command-line interface for ZeroPath.

Commands:
  analyze       Analyze contracts from a local path or GitHub URL.
  infer         Run Phase 2 invariant inference on a protocol graph.
  attack        Run Phase 3 adversarial swarm on an invariant report.
  sequence      Run Phase 4 transaction sequence + PoC generation.
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

# Matches 0x-prefixed 20-byte hex addresses (case-insensitive)
_ETH_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


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
@click.option(
    "--chain",
    default=None,
    help="Chain name or ID for on-chain address resolution (e.g. mainnet, polygon, 42161).",
)
@click.option(
    "--etherscan-key",
    default=None,
    help="Etherscan / block-explorer API key for source fetching.",
)
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
    chain: Optional[str],
    etherscan_key: Optional[str],
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
      - A contract address: 0x1234...abcd  (fetches verified source on-chain)
    """
    settings: Settings = ctx.obj["settings"]
    tmp_dir: Optional[Path] = None

    try:
        # --- Resolve source to a local path ---
        contract_path = _resolve_source(
            source,
            settings,
            chain=chain or settings.default_chain,
            etherscan_key=etherscan_key or settings.etherscan_api_key,
        )

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
# infer command (Phase 2)
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("graph_file", type=Path)
@click.option(
    "--output", "-o",
    type=Path,
    default=Path("output/invariants.json"),
    show_default=True,
    help="Output JSON file for the invariant report.",
)
@click.option(
    "--protocol-name", "-n",
    default="unknown",
    show_default=True,
    help="Human-readable protocol name.",
)
@click.option(
    "--min-severity",
    default="low",
    type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
    show_default=True,
    help="Only display invariants at or above this severity.",
)
@click.pass_context
def infer(
    ctx: click.Context,
    graph_file: Path,
    output: Path,
    protocol_name: str,
    min_severity: str,
) -> None:
    """
    Run Phase 2 invariant inference on a saved protocol graph.

    GRAPH_FILE is a JSON file produced by the `analyze` command.

    Example::

        zeropath analyze ./contracts -o output/graph.json
        zeropath infer output/graph.json -n "MyProtocol" -o output/invariants.json
    """
    from zeropath.invariants import InvariantInferenceEngine
    from zeropath.invariants.models import InvariantSeverity

    _SEVERITY_LEVELS = {
        "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
    }
    min_level = _SEVERITY_LEVELS[min_severity.lower()]

    try:
        with open(graph_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        graph = ProtocolGraph.model_validate(data)
    except Exception as exc:
        console.print(f"[red]✗ Failed to load graph:[/red] {exc}")
        raise click.Exit(1)

    with console.status("[bold green]Running invariant inference (Phase 2)…"):
        engine = InvariantInferenceEngine()
        report = engine.analyse(graph, protocol_name=protocol_name)

    # Save JSON
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        json.dump(report.model_dump(by_alias=True), f, indent=2, default=str)
    console.print(f"[green]✓[/green] Invariant report saved → {output}")

    # Display summary
    _display_invariant_summary(report, min_level, _SEVERITY_LEVELS)


def _display_invariant_summary(report: "InvariantReport", min_level: int, levels: dict) -> None:
    from rich.markup import escape
    from zeropath.invariants.models import InvariantSeverity

    _SEV_COLOR = {
        InvariantSeverity.CRITICAL: "red bold",
        InvariantSeverity.HIGH: "red",
        InvariantSeverity.MEDIUM: "yellow",
        InvariantSeverity.LOW: "blue",
        InvariantSeverity.INFO: "dim",
    }

    visible = [
        i for i in report.invariants
        if levels.get(i.severity.value, 99) <= min_level
    ]

    summary_table = Table(title=f"Invariant Report — {report.protocol_name}", show_lines=True)
    summary_table.add_column("Severity", style="bold", min_width=10)
    summary_table.add_column("Type", style="cyan")
    summary_table.add_column("Confidence", justify="right")
    summary_table.add_column("Description")

    for inv in visible:
        color = _SEV_COLOR.get(inv.severity, "white")
        summary_table.add_row(
            Text(inv.severity.value.upper(), style=color),
            inv.type.value,
            f"{inv.confidence:.0%}",
            escape(inv.description[:120]),
        )

    console.print(summary_table)

    # Totals panel
    by_sev = {}
    for inv in report.invariants:
        by_sev[inv.severity.value] = by_sev.get(inv.severity.value, 0) + 1

    totals = " | ".join(
        f"[{_SEV_COLOR.get(InvariantSeverity(k), 'white')}]{k.upper()}: {v}[/]"
        for k, v in sorted(by_sev.items(), key=lambda x: levels.get(x[0], 99))
    )
    console.print(Panel(
        f"Total invariants: [bold]{len(report.invariants)}[/bold]  |  {totals}\n"
        f"Oracle dependencies: [bold]{len(report.oracle_dependencies)}[/bold]",
        title="Summary",
        expand=False,
    ))


# ---------------------------------------------------------------------------
# attack command (Phase 3)
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("invariants_file", type=Path)
@click.argument("graph_file", type=Path)
@click.option(
    "--output", "-o",
    type=Path,
    default=Path("output/attack_report.json"),
    show_default=True,
    help="Output JSON file for the swarm attack report.",
)
@click.option(
    "--protocol-name", "-n",
    default="",
    help="Protocol name override (defaults to value from invariant report).",
)
@click.option(
    "--min-confidence",
    default=0.40,
    show_default=True,
    type=float,
    help="Minimum hypothesis confidence to display (0.0–1.0).",
)
@click.option(
    "--debate-rounds",
    default=2,
    show_default=True,
    type=int,
    help="Number of inter-agent debate rounds.",
)
@click.option(
    "--workers",
    default=4,
    show_default=True,
    type=int,
    help="Parallel worker count for agent execution.",
)
@click.pass_context
def attack(
    ctx: click.Context,
    invariants_file: Path,
    graph_file: Path,
    output: Path,
    protocol_name: str,
    min_confidence: float,
    debate_rounds: int,
    workers: int,
) -> None:
    """
    Run Phase 3 adversarial swarm on an invariant report.

    INVARIANTS_FILE is produced by the `infer` command.
    GRAPH_FILE is produced by the `analyze` command.

    Example::

        zeropath analyze ./contracts -o output/graph.json
        zeropath infer output/graph.json -n "MyProtocol" -o output/invariants.json
        zeropath attack output/invariants.json output/graph.json -o output/attack_report.json
    """
    from zeropath.adversarial import SwarmOrchestrator
    from zeropath.invariants.models import InvariantReport

    # Load invariant report
    try:
        with open(invariants_file, "r", encoding="utf-8") as f:
            inv_data = json.load(f)
        inv_report = InvariantReport.model_validate(inv_data)
    except Exception as exc:
        console.print(f"[red]✗ Failed to load invariants file:[/red] {exc}")
        raise click.Exit(1)

    # Load protocol graph
    try:
        with open(graph_file, "r", encoding="utf-8") as f:
            graph_data = json.load(f)
        graph = ProtocolGraph.model_validate(graph_data)
    except Exception as exc:
        console.print(f"[red]✗ Failed to load graph file:[/red] {exc}")
        raise click.Exit(1)

    if protocol_name:
        inv_report.protocol_name = protocol_name

    with console.status("[bold red]Running adversarial swarm (Phase 3)…"):
        swarm = SwarmOrchestrator(max_workers=workers, debate_rounds=debate_rounds)
        swarm_report = swarm.run(inv_report, graph)

    # Save JSON
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        json.dump(swarm_report.model_dump(by_alias=True), f, indent=2, default=str)
    console.print(f"[green]✓[/green] Attack report saved → {output}")

    # Display summary
    _display_attack_summary(swarm_report, min_confidence)


def _display_attack_summary(swarm_report: "SwarmReport", min_confidence: float) -> None:
    from rich.markup import escape
    from zeropath.adversarial.models import HypothesisStatus

    _STATUS_COLOR = {
        HypothesisStatus.CONSENSUS: "red bold",
        HypothesisStatus.ENDORSED: "red",
        HypothesisStatus.CHALLENGED: "yellow",
        HypothesisStatus.PROPOSED: "white",
        HypothesisStatus.REJECTED: "dim",
    }

    visible = [
        h for h in swarm_report.hypotheses
        if h.confidence >= min_confidence
        and h.status != HypothesisStatus.REJECTED
    ]

    table = Table(
        title=f"Attack Hypotheses — {swarm_report.protocol_name}",
        show_lines=True,
    )
    table.add_column("Status", min_width=12)
    table.add_column("Attack Class", style="cyan")
    table.add_column("Confidence", justify="right")
    table.add_column("Agent")
    table.add_column("Title")

    for hyp in visible:
        color = _STATUS_COLOR.get(hyp.status, "white")
        table.add_row(
            Text(hyp.status.value.upper(), style=color),
            hyp.attack_class.value,
            f"{hyp.confidence:.0%}",
            hyp.proposed_by.replace("Agent", ""),
            escape(hyp.title[:80]),
        )

    console.print(table)

    # Stats panel
    meta = swarm_report.analysis_metadata
    console.print(Panel(
        f"Total hypotheses: [bold]{len(swarm_report.hypotheses)}[/bold]  |  "
        f"Shown (≥{min_confidence:.0%}): [bold]{len(visible)}[/bold]  |  "
        f"Consensus: [red bold]{len(swarm_report.critical_hypotheses)}[/red bold]  |  "
        f"Rejected: [dim]{swarm_report.rejected_count}[/dim]\n"
        f"Agents: {meta.get('agents', [])}  |  "
        f"Debate rounds: {meta.get('debate_rounds', 0)}  |  "
        f"Time: {meta.get('elapsed_seconds', 0):.1f}s",
        title="Swarm Summary",
        expand=False,
    ))


# ---------------------------------------------------------------------------
# sequence command (Phase 4)
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("attack_file", type=Path)
@click.argument("graph_file", type=Path)
@click.option(
    "--output-dir", "-o",
    type=Path,
    default=Path("output/sequences"),
    show_default=True,
    help="Directory to write sequence JSON + PoC test files.",
)
@click.option(
    "--framework",
    type=click.Choice(["foundry", "hardhat", "both"], case_sensitive=False),
    default="both",
    show_default=True,
    help="Test framework(s) for generated PoC code.",
)
@click.option(
    "--min-confidence",
    default=0.40,
    show_default=True,
    type=float,
    help="Minimum hypothesis confidence to sequence.",
)
@click.pass_context
def sequence(
    ctx: click.Context,
    attack_file: Path,
    graph_file: Path,
    output_dir: Path,
    framework: str,
    min_confidence: float,
) -> None:
    """
    Run Phase 4 transaction sequence generation on a swarm attack report.

    ATTACK_FILE is produced by the `attack` command.
    GRAPH_FILE is produced by the `analyze` command.

    Outputs:
      - sequence_report.json  (full structured report)
      - sequences/*.t.sol     (Foundry tests)
      - sequences/*.test.ts   (Hardhat tests)

    Example::

        zeropath attack output/invariants.json output/graph.json -o output/attack_report.json
        zeropath sequence output/attack_report.json output/graph.json -o output/sequences/
    """
    from zeropath.adversarial.models import SwarmReport
    from zeropath.sequencer import SequenceOrchestrator, TestFramework

    # Load swarm report
    try:
        with open(attack_file, "r", encoding="utf-8") as f:
            attack_data = json.load(f)
        swarm_report = SwarmReport.model_validate(attack_data)
    except Exception as exc:
        console.print(f"[red]✗ Failed to load attack file:[/red] {exc}")
        raise click.Exit(1)

    # Load protocol graph
    try:
        with open(graph_file, "r", encoding="utf-8") as f:
            graph_data = json.load(f)
        graph = ProtocolGraph.model_validate(graph_data)
    except Exception as exc:
        console.print(f"[red]✗ Failed to load graph file:[/red] {exc}")
        raise click.Exit(1)

    fw_map = {"foundry": TestFramework.FOUNDRY, "hardhat": TestFramework.HARDHAT, "both": TestFramework.BOTH}
    fw = fw_map[framework.lower()]

    with console.status("[bold blue]Generating transaction sequences (Phase 4)…"):
        orchestrator = SequenceOrchestrator(frameworks=fw, min_confidence=min_confidence)
        seq_report = orchestrator.run(swarm_report, graph)

    # Write outputs
    output_dir.mkdir(parents=True, exist_ok=True)

    # Main report JSON
    report_path = output_dir / "sequence_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(seq_report.model_dump(by_alias=True), f, indent=2, default=str)
    console.print(f"[green]✓[/green] Sequence report → {report_path}")

    # Write individual PoC files
    poc_dir = output_dir / "poc"
    poc_dir.mkdir(exist_ok=True)
    for seq in seq_report.sequences:
        if seq.foundry_test:
            fpath = poc_dir / seq.foundry_test.filename
            fpath.write_text(seq.foundry_test.code, encoding="utf-8")
        if seq.hardhat_test:
            hpath = poc_dir / seq.hardhat_test.filename
            hpath.write_text(seq.hardhat_test.code, encoding="utf-8")

    console.print(f"[green]✓[/green] PoC files → {poc_dir}/")

    # Display summary
    _display_sequence_summary(seq_report)


def _display_sequence_summary(seq_report: "SequenceReport") -> None:
    from rich.markup import escape
    from zeropath.sequencer.models import SequenceStatus

    _STATUS_COLOR = {
        SequenceStatus.GENERATED: "cyan",
        SequenceStatus.SIMULATION_PASSED: "green",
        SequenceStatus.VALIDATED: "green bold",
        SequenceStatus.SIMULATION_FAILED: "red",
        SequenceStatus.REJECTED: "dim",
    }

    table = Table(
        title=f"Transaction Sequences — {seq_report.protocol_name}",
        show_lines=True,
    )
    table.add_column("Attack Class", style="cyan")
    table.add_column("Completeness", justify="right")
    table.add_column("PoC Ready", justify="center")
    table.add_column("Manual Params", justify="center")
    table.add_column("Title")

    for seq in seq_report.sequences:
        has_poc = "✓" if (seq.foundry_test or seq.hardhat_test) else "✗"
        has_manual = str(len(seq.requires_manual_params)) if seq.requires_manual_params else "—"
        table.add_row(
            seq.attack_class,
            f"{seq.completeness_score:.0%}",
            has_poc,
            has_manual,
            escape(seq.hypothesis_title[:70]),
        )

    console.print(table)
    console.print(Panel(
        f"Hypotheses processed: [bold]{seq_report.total_hypotheses_input}[/bold]  |  "
        f"Sequences: [bold]{seq_report.sequences_generated}[/bold]  |  "
        f"With PoC: [green bold]{seq_report.sequences_with_full_poc}[/green bold]  |  "
        f"Ready to simulate: [cyan]{len(seq_report.ready_to_simulate)}[/cyan]",
        title="Phase 4 Summary",
        expand=False,
    ))


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


def _resolve_source(
    source: str,
    settings: Settings,
    chain: str = "mainnet",
    etherscan_key: Optional[str] = None,
) -> Path:
    """
    Resolve SOURCE to a local Path.

    Handles:
      - Local file / directory paths
      - GitHub URLs and owner/repo shorthands
      - Ethereum contract addresses (0x-prefixed, 20 bytes)
    """
    # Already a local path?
    local = Path(source)
    if local.exists():
        return local.resolve()

    # Ethereum contract address?
    if _ETH_ADDRESS_RE.match(source):
        return _fetch_onchain(
            address=source,
            chain=chain,
            settings=settings,
            etherscan_key=etherscan_key,
        )

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
        f"'{source}' is not a recognised input. Expected:\n"
        "  - A local file or directory path\n"
        "  - A GitHub URL or owner/repo shorthand\n"
        "  - An Ethereum address: 0x1234...abcd"
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


def _fetch_onchain(
    address: str,
    chain: str,
    settings: Settings,
    etherscan_key: Optional[str],
) -> Path:
    """Fetch contract source (or bytecode) from on-chain APIs into a temp dir."""
    from zeropath.onchain_fetcher import OnChainFetcher

    console.print(
        f"[bold]Fetching on-chain source[/bold] {address} on [cyan]{chain}[/cyan]…"
    )

    fetcher = OnChainFetcher(
        etherscan_api_key=etherscan_key,
        rpc_url=settings.rpc_url,
    )

    try:
        on_chain_src = fetcher.fetch(address, chain)
    except Exception as exc:
        raise ZeropathError(f"On-chain fetch failed for {address}: {exc}") from exc

    if on_chain_src.source_available:
        console.print(
            f"[green]✓[/green] Source found via [bold]{on_chain_src.fetch_tier}[/bold] "
            f"({len(on_chain_src.source_files)} file(s)) — "
            f"contract: [cyan]{on_chain_src.contract_name}[/cyan]"
        )
    else:
        console.print(
            "[yellow]⚠[/yellow] No verified source found — "
            "falling back to bytecode decompilation."
        )

    local_dir = fetcher.write_sources_to_tempdir(on_chain_src)
    return local_dir


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
