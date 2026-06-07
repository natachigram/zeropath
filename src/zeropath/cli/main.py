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
from typing import Any, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if not hasattr(click, "Exit"):
    click.Exit = click.exceptions.Exit

from zeropath.config import Settings
from zeropath.exceptions import GitHubIngestionError, ZeropathError
from zeropath.logging_config import configure_logging, get_logger

try:
    from zeropath.graph_builder import ProtocolGraphBuilder
except Exception:  # pragma: no cover - optional legacy dependency path
    ProtocolGraphBuilder = None

try:
    from zeropath.graph_db import Neo4jGraphDB
except Exception:  # pragma: no cover - optional legacy dependency path
    Neo4jGraphDB = None

try:
    from zeropath.models import ProtocolGraph
except Exception:  # pragma: no cover - optional legacy dependency path
    ProtocolGraph = None

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


@cli.command()
@click.argument(
    "repo_path",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option(
    "--platform",
    type=click.Choice(["cantina", "code4rena", "sherlock", "immunefi", "generic"]),
    default="generic", show_default=True,
    help="Target contest platform — drives output formatting.",
)
@click.option(
    "-n", "--contest-name", default="", help="Human-readable contest name."
)
@click.option(
    "--scope",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="File listing in-scope Solidity files (one per line, repo-relative).",
)
@click.option(
    "--out", "-o",
    type=click.Path(path_type=Path),
    default=Path("output/contest-submissions.json"),
    show_default=True,
    help="Path for the submission JSON.",
)
@click.option(
    "--invariants",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to a Phase 2 InvariantReport JSON to enrich LLM context.",
)
@click.option(
    "--kg-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help=(
        "Directory containing a Phase 8 InMemoryKGStore snapshot "
        "(kg.json). Enables RAG over prior contest findings."
    ),
)
@click.option(
    "--llm-budget-usd", type=float, default=200.0, show_default=True,
    help="Hard cap on LLM spend for this run.",
)
@click.option(
    "--confidence-threshold", type=float, default=0.70, show_default=True,
    help="Minimum finding confidence required for submission.",
)
@click.option(
    "--severity-floor",
    type=click.Choice(["critical", "high", "medium", "low", "informational"]),
    default="medium", show_default=True,
    help="Lowest severity that will be submitted.",
)
@click.option(
    "--workers", type=int, default=4, show_default=True,
    help="Parallel per-file audit workers.",
)
@click.option(
    "--no-llm", is_flag=True, help="Disable LLM Reasoner (skeleton run).",
)
@click.option(
    "--no-spec-miner", is_flag=True, help="Skip spec-mining stage.",
)
@click.option(
    "--no-foundry", is_flag=True, help="Skip Foundry PoC verification.",
)
@click.option(
    "--no-contrarian", is_flag=True, help="Skip LLM contrarian review pass.",
)
@click.pass_context
def contest(
    ctx: click.Context,
    repo_path: Path,
    platform: str,
    contest_name: str,
    scope: Optional[Path],
    out: Path,
    invariants: Optional[Path],
    kg_dir: Optional[Path],
    llm_budget_usd: float,
    confidence_threshold: float,
    severity_floor: str,
    workers: int,
    no_llm: bool,
    no_spec_miner: bool,
    no_foundry: bool,
    no_contrarian: bool,
) -> None:
    """Run the contest-winning pipeline against a target repo.

    Examples::

        zeropath contest ./contracts \\
            --platform cantina \\
            --scope ./scope.txt \\
            --llm-budget-usd 200 \\
            --confidence-threshold 0.70 \\
            -o output/cantina-submissions.json
    """
    import json as _json

    from zeropath.contest import (
        ContestConfig, ContestOrchestrator, ContestPlatform,
    )
    from zeropath.invariants.models import InvariantReport
    from zeropath.knowledge import (
        InMemoryKGStore, KnowledgeGraphOrchestrator,
    )

    scope_files: list[str] = []
    if scope:
        scope_files = [
            line.strip()
            for line in scope.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    knowledge: Optional[KnowledgeGraphOrchestrator] = None
    if kg_dir:
        store = InMemoryKGStore()
        snap = kg_dir / "kg.json"
        if snap.exists():
            try:
                store.restore(snap)
                knowledge = KnowledgeGraphOrchestrator(store)
                click.echo(f"[zeropath] loaded KG from {snap}", err=True)
            except Exception as exc:
                click.echo(f"[zeropath] failed to restore KG: {exc}", err=True)

    inv_report = None
    if invariants:
        try:
            inv_report = InvariantReport.model_validate_json(
                invariants.read_text(encoding="utf-8"),
            )
            click.echo(
                f"[zeropath] loaded {len(inv_report.invariants)} Phase 2 invariants",
                err=True,
            )
        except Exception as exc:
            click.echo(f"[zeropath] failed to load --invariants: {exc}", err=True)

    cfg = ContestConfig(
        platform=ContestPlatform(platform),
        contest_name=contest_name,
        repo_path=str(repo_path),
        scope_files=scope_files,
        llm_budget_usd=llm_budget_usd,
        submit_confidence_threshold=confidence_threshold,
        submit_severity_floor=severity_floor,
        parallel_workers=max(1, workers),
        use_llm=not no_llm,
        use_spec_miner=not no_spec_miner,
        use_foundry_verifier=not no_foundry,
        use_contrarian=not no_contrarian,
    )

    click.echo(
        f"[zeropath] contest mode: platform={cfg.platform.value} "
        f"repo={cfg.repo_path} scope_files={len(scope_files) or 'auto'} "
        f"llm={cfg.use_llm} spec={cfg.use_spec_miner} foundry={cfg.use_foundry_verifier}",
        err=True,
    )

    report = ContestOrchestrator(
        cfg,
        knowledge=knowledge,
        inferred_invariant_report=inv_report,
    ).run()

    # Render the actionable subset using the platform formatter for the
    # final on-disk file. The full ContestReport is dumped alongside.
    actionable = report.ready_to_submit
    payload = {
        "config": cfg.model_dump(mode="json"),
        "summary": {
            "files_scanned": report.files_scanned,
            "raw_findings": report.raw_findings_count,
            "actionable_findings": len(actionable),
            "submitted_count": report.submitted_count,
            "discarded_count": report.discarded_count,
            "by_severity": report.findings_by_severity,
            "llm_spent_usd": report.llm_spent_usd,
            "llm_calls": report.llm_calls,
            "elapsed_seconds": report.elapsed_seconds,
        },
        "submissions": [
            {
                "rank": s.rank,
                "disposition": s.disposition.value,
                "finding": s.finding.model_dump(mode="json"),
                "rendered_payload": s.rendered_payload,
            }
            for s in actionable
        ],
        "all_submissions": [s.model_dump(mode="json") for s in report.submissions],
        "metadata": report.analysis_metadata,
    }

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(_json.dumps(payload, indent=2, default=str), encoding="utf-8")

    # Pretty stdout summary.
    console = Console()
    table = Table(title=f"Contest report — {cfg.platform.value}", show_header=True)
    table.add_column("Rank"); table.add_column("Severity")
    table.add_column("Confidence"); table.add_column("Dup%")
    table.add_column("Class"); table.add_column("Title")
    for s in actionable[:20]:
        table.add_row(
            str(s.rank),
            s.finding.severity.upper(),
            f"{s.finding.confidence:.2f}",
            f"{int(s.finding.duplicate_likelihood * 100)}%",
            s.finding.attack_class,
            s.finding.title[:60],
        )
    console.print(table)
    click.echo(f"[zeropath] wrote {len(actionable)} actionable submissions → {out}", err=True)
    click.echo(
        f"[zeropath] LLM spend: ${report.llm_spent_usd:.4f} "
        f"({report.llm_calls} calls)",
        err=True,
    )


# ---------------------------------------------------------------------------
# Evidence-first engine CLI
# ---------------------------------------------------------------------------


@cli.command("init")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--write-agent-files", is_flag=True, help="Copy agent integration templates into .zeropath/exports.")
def zp_init(repo: Path, write_agent_files: bool) -> None:
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


@cli.command("status")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def zp_status(repo: Path) -> None:
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


@cli.command("ingest")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--docs", multiple=True, type=click.Path(path_type=Path), help="Documentation path to associate with the project.")
@click.option("--scope", multiple=True, type=click.Path(path_type=Path), help="Scope file to associate with the project.")
def zp_ingest(repo: Path, docs: tuple[Path, ...], scope: tuple[Path, ...]) -> None:
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


@cli.command("understand")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def zp_understand(repo: Path) -> None:
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


@cli.command("hunt")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--mode", type=click.Choice(["critical", "high-medium", "qa"]), default="critical", show_default=True)
@click.option("--limit", type=int, default=5, show_default=True)
@click.option("--focus", default=None, help="Optional focus term, such as oracle or vault.")
def zp_hunt(repo: Path, mode: str, limit: int, focus: Optional[str]) -> None:
    """Generate evidence-seeking hypotheses, not final findings."""
    from zeropath.core.candidates import generate_candidates
    from zeropath.core.storage import Storage

    storage = Storage(repo)
    try:
        candidates = generate_candidates(storage, mode=mode, limit=limit, focus=focus)
    except Exception as exc:
        console.print(f"[red]Hunt failed:[/red] {exc}")
        raise click.Exit(1)
    table = Table(title="Candidate hypotheses", show_header=True)
    table.add_column("ID"); table.add_column("Severity"); table.add_column("Title"); table.add_column("Status")
    for candidate in candidates:
        table.add_row(candidate.id, candidate.severity_guess or "unknown", candidate.title, candidate.status)
    if not candidates:
        table.add_row("-", "-", "No template matched indexed evidence.", "-")
    console.print(table)
    console.print("[yellow]Hypotheses are not findings. Run `zeropath prove` and `zeropath judge` before reporting.[/yellow]")


@cli.group("candidates")
def zp_candidates() -> None:
    """List, inspect, and update candidate hypotheses."""


@zp_candidates.command("list")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def zp_candidates_list(repo: Path) -> None:
    from zeropath.core.evidence import evidence_score
    from zeropath.core.storage import Storage

    storage = Storage(repo)
    candidates = storage.list_candidates()
    table = Table(title="ZeroPath candidates", show_header=True)
    table.add_column("ID"); table.add_column("Status"); table.add_column("Evidence"); table.add_column("Title")
    for candidate in candidates:
        table.add_row(candidate.id, candidate.status, str(evidence_score(candidate.evidence)), candidate.title)
    if not candidates:
        table.add_row("-", "-", "-", "No candidates yet.")
    console.print(table)


@zp_candidates.command("show")
@click.argument("candidate_id")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def zp_candidates_show(candidate_id: str, repo: Path) -> None:
    from zeropath.core.storage import Storage

    candidate = Storage(repo).load_candidate(candidate_id)
    if candidate is None:
        console.print(f"[red]Candidate not found:[/red] {candidate_id}")
        raise click.Exit(1)
    console.print_json(json.dumps(candidate.model_dump(mode="json"), indent=2))


@zp_candidates.command("update")
@click.argument("candidate_id")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--status", required=True, type=click.Choice([
    "observation", "hypothesis", "path_identified", "state_planned", "poc_generated",
    "poc_passed", "judge_passed", "report_ready", "rejected", "stale", "needs_evidence",
]))
@click.option("--reason", default=None, help="Evidence or rejection reason.")
def zp_candidates_update(candidate_id: str, repo: Path, status: str, reason: Optional[str]) -> None:
    from zeropath.core.storage import Storage

    try:
        candidate = Storage(repo).update_candidate_status(candidate_id, status, reason)
    except Exception as exc:
        console.print(f"[red]Update failed:[/red] {exc}")
        raise click.Exit(1)
    console.print(f"[green]{candidate.id}[/green] -> {candidate.status}")


@zp_candidates.command("evidence")
@click.argument("candidate_id")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--root-cause-lines", is_flag=True, help="Mark root cause source lines as evidenced.")
@click.option("--attacker-path", is_flag=True, help="Mark attacker transaction path as evidenced.")
@click.option("--state-preconditions", is_flag=True, help="Mark reachable state preconditions as evidenced.")
@click.option("--known-issues-checked", is_flag=True, help="Mark known-issue triage as complete.")
@click.option("--duplicate-risk-checked", is_flag=True, help="Mark duplicate-risk triage as complete.")
@click.option("--live-config-checked", is_flag=True, help="Mark deployment/fork configuration as checked.")
@click.option("--duplicate-risk", type=click.Choice(["none", "low", "medium", "high"], case_sensitive=False))
@click.option("--known-issue-risk", type=click.Choice(["none", "low", "medium", "high"], case_sensitive=False))
@click.option("--chain-id", type=int)
@click.option("--fork-block", type=int)
@click.option("--poc-path", type=click.Path(path_type=Path))
@click.option("--trace-path", type=click.Path(path_type=Path))
@click.option("--forge-result", type=click.Choice(["passed", "failed", "unavailable", "not_run"], case_sensitive=False))
@click.option("--invariant-test-result", type=click.Choice(["passed", "failed", "unavailable", "not_run"], case_sensitive=False))
@click.option("--impact-measured", is_flag=True)
@click.option("--profit-measured", is_flag=True)
@click.option("--amount", default=None, help="Concrete measured impact amount or bound.")
@click.option("--note", "notes", multiple=True, help="Append an evidence note. Repeatable.")
def zp_candidates_evidence(
    candidate_id: str,
    repo: Path,
    root_cause_lines: bool,
    attacker_path: bool,
    state_preconditions: bool,
    known_issues_checked: bool,
    duplicate_risk_checked: bool,
    live_config_checked: bool,
    duplicate_risk: Optional[str],
    known_issue_risk: Optional[str],
    chain_id: Optional[int],
    fork_block: Optional[int],
    poc_path: Optional[Path],
    trace_path: Optional[Path],
    forge_result: Optional[str],
    invariant_test_result: Optional[str],
    impact_measured: bool,
    profit_measured: bool,
    amount: Optional[str],
    notes: tuple[str, ...],
) -> None:
    """Record concrete evidence and triage facts for a candidate."""
    from zeropath.core.candidates import update_candidate_evidence
    from zeropath.core.evidence import evidence_score, missing_evidence
    from zeropath.core.storage import Storage

    try:
        candidate = update_candidate_evidence(
            Storage(repo),
            candidate_id,
            root_cause_lines_present=root_cause_lines,
            attacker_path_present=attacker_path,
            state_preconditions_present=state_preconditions,
            known_issues_checked=known_issues_checked,
            duplicate_risk_checked=duplicate_risk_checked,
            live_config_checked=live_config_checked,
            duplicate_risk=duplicate_risk,
            known_issue_risk=known_issue_risk,
            chain_id=chain_id,
            fork_block=fork_block,
            poc_path=poc_path,
            trace_path=trace_path,
            forge_result=forge_result,
            invariant_test_result=invariant_test_result,
            impact_measured=impact_measured,
            profit_measured=profit_measured,
            amount=amount,
            notes=list(notes),
        )
    except Exception as exc:
        console.print(f"[red]Evidence update failed:[/red] {exc}")
        raise click.Exit(1)

    table = Table(title=f"Evidence updated: {candidate.id}", show_header=True)
    table.add_column("Field"); table.add_column("Value")
    table.add_row("score", str(evidence_score(candidate.evidence)))
    table.add_row("status", candidate.status)
    table.add_row("duplicate_risk", candidate.duplicate_risk or "unknown")
    table.add_row("known_issue_risk", candidate.known_issue_risk or "unknown")
    table.add_row("missing", ", ".join(missing_evidence(candidate.evidence)) or "none")
    console.print(table)


@zp_candidates.command("plan")
@click.argument("candidate_id")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def zp_candidates_plan(candidate_id: str, repo: Path) -> None:
    """Build and save a proof-state plan for a candidate."""
    from zeropath.core.state_plan import build_candidate_state_plan
    from zeropath.core.storage import Storage

    try:
        plan = build_candidate_state_plan(Storage(repo), candidate_id)
    except Exception as exc:
        console.print(f"[red]State plan failed:[/red] {exc}")
        raise click.Exit(1)

    table = Table(title=f"State plan: {plan.candidate_id}", show_header=True)
    table.add_column("Field"); table.add_column("Value")
    table.add_row("confidence", plan.confidence)
    table.add_row("setup_steps", str(len(plan.setup_steps)))
    table.add_row("transaction_steps", str(len(plan.transaction_steps)))
    table.add_row("missing_dependencies", str(len(plan.missing_dependencies)))
    table.add_row("evidence_to_collect", str(len(plan.evidence_to_collect)))
    table.add_row("artifact", plan.artifact_path or "not saved")
    console.print(table)

    console.print("[bold]Setup steps[/bold]")
    for step in plan.setup_steps:
        console.print(f"- {step}")
    console.print("[bold]Missing dependencies[/bold]")
    for item in plan.missing_dependencies or ["None"]:
        console.print(f"- {item}")


@cli.command("prove")
@click.argument("candidate_id")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--backend", type=click.Choice(["foundry"]), default="foundry", show_default=True)
@click.option("--write-test-dir", is_flag=True, help="Also write a Foundry test under test/zeropath if safe.")
@click.option("--force", is_flag=True, help="Allow overwriting generated Foundry test file.")
@click.option("--run/--no-run", default=True, show_default=True, help="Run backend proof if available.")
def zp_prove(candidate_id: str, repo: Path, backend: str, write_test_dir: bool, force: bool, run: bool) -> None:
    """Generate a candidate proof skeleton and optionally run a backend."""
    from zeropath.adapters.evm import EVMAdapter
    from zeropath.adapters.evm.forge import run_forge_test
    from zeropath.adapters.evm.foundry import write_candidate_test
    from zeropath.core.storage import Storage

    storage = Storage(repo)
    candidate = storage.load_candidate(candidate_id)
    if candidate is None:
        console.print(f"[red]Candidate not found:[/red] {candidate_id}")
        raise click.Exit(1)
    adapter = EVMAdapter(repo)
    poc = adapter.generate_poc(candidate)
    if not poc:
        console.print("[yellow]PoC could not be generated by the adapter.[/yellow]")
        raise click.Exit(1)
    artifact = storage.append_artifact(Path("pocs") / f"{candidate.id.replace('-', '_')}.t.sol", poc, overwrite=True)
    candidate.evidence.poc_path = str(artifact)
    candidate.status = "poc_generated"
    if write_test_dir:
        try:
            test_path = write_candidate_test(repo, candidate, force=force)
            candidate.evidence.notes.append(f"Foundry test written to {test_path}")
        except FileExistsError as exc:
            console.print(f"[red]{exc}[/red]")
            raise click.Exit(1)
    if run and backend == "foundry":
        result = run_forge_test(repo)
        candidate.evidence.forge_result = result.get("status")
        candidate.evidence.notes.append(result.get("message") or f"forge test status: {result.get('status')}")
        if result.get("status") == "passed":
            candidate.status = "poc_passed"
    storage.save_candidate(candidate)
    console.print(f"[green]PoC skeleton:[/green] {artifact}")
    console.print(f"Forge result: {candidate.evidence.forge_result or 'not run'}")


@cli.command("judge")
@click.argument("candidate_id")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def zp_judge(candidate_id: str, repo: Path) -> None:
    """Run skeptical judge checks for one candidate."""
    from zeropath.core.judge import judge_candidate
    from zeropath.core.storage import Storage

    storage = Storage(repo)
    candidate = storage.load_candidate(candidate_id)
    if candidate is None:
        console.print(f"[red]Candidate not found:[/red] {candidate_id}")
        raise click.Exit(1)
    result = judge_candidate(candidate, storage)
    table = Table(title=f"Judge {candidate_id}", show_header=True)
    table.add_column("Check"); table.add_column("Value")
    table.add_row("report_ready", str(result.report_ready))
    table.add_row("severity", result.severity)
    table.add_row("funds_at_risk", str(result.funds_at_risk))
    table.add_row("attacker_realistic", str(result.attacker_realistic))
    table.add_row("state_reachable", str(result.state_reachable))
    table.add_row("live_config_reachable", str(result.live_config_reachable))
    table.add_row("blocking", "; ".join(result.blocking_objections) or "none")
    console.print(table)
    if result.required_next_steps:
        console.print("[yellow]Next evidence steps:[/yellow]")
        for step in result.required_next_steps:
            console.print(f"- {step}")


@cli.command("report")
@click.argument("candidate_id")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--format", "report_format", type=click.Choice(["code4rena", "sherlock", "cantina", "internal"]), default="code4rena", show_default=True)
@click.option("--draft", is_flag=True, help="Export a clearly marked draft even if judge has not passed.")
def zp_report(candidate_id: str, repo: Path, report_format: str, draft: bool) -> None:
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


@cli.group("memory")
def zp_memory() -> None:
    """Manage the research ledger."""


@zp_memory.command("search")
@click.argument("query")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--scope", default=None)
@click.option("--type", "memory_type", default=None)
@click.option("--tag", "tags", multiple=True)
def zp_memory_search(query: str, repo: Path, scope: Optional[str], memory_type: Optional[str], tags: tuple[str, ...]) -> None:
    from zeropath.core.memory import search_memory
    from zeropath.core.storage import Storage

    results = search_memory(Storage(repo), query, scope=scope, memory_type=memory_type, tags=list(tags))
    _print_memory_table(results, "Memory search")


@zp_memory.command("list")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--type", "memory_type", default=None)
def zp_memory_list(repo: Path, memory_type: Optional[str]) -> None:
    from zeropath.core.storage import Storage

    items = Storage(repo).list_memory()
    if memory_type:
        items = [item for item in items if item.memory_type == memory_type]
    _print_memory_table(items, "Memory")


@zp_memory.command("add")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--type", "memory_type", required=True)
@click.option("--content", required=True)
@click.option("--scope", default="current_project", show_default=True)
@click.option("--confidence", default="inferred", show_default=True)
@click.option("--source", default="manual", show_default=True)
@click.option("--tag", "tags", multiple=True)
@click.option("--user-approved", is_flag=True, help="Allow durable research_lesson admission.")
def zp_memory_add(
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

    decision, memory = propose_memory(
        Storage(repo),
        content=content,
        memory_type=memory_type,
        scope=scope,
        confidence=confidence,
        source=source,
        tags=list(tags),
        context={"user_approved": user_approved},
    )
    if decision.save and memory:
        console.print(f"[green]Saved[/green] {memory.id}: {decision.reason}")
    else:
        console.print(f"[yellow]Not saved:[/yellow] {decision.reason}")


@zp_memory.command("forget")
@click.argument("memory_id")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def zp_memory_forget(memory_id: str, repo: Path) -> None:
    from zeropath.core.storage import Storage

    removed = Storage(repo).delete_record("memory", memory_id)
    console.print("[green]forgotten[/green]" if removed else "[yellow]not found[/yellow]")


@zp_memory.command("mark-stale")
@click.argument("memory_id")
@click.option("--reason", required=True)
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def zp_memory_mark_stale(memory_id: str, reason: str, repo: Path) -> None:
    from zeropath.core.memory import mark_memory_stale
    from zeropath.core.storage import Storage

    ok = mark_memory_stale(Storage(repo), memory_id, reason)
    console.print("[green]marked stale[/green]" if ok else "[yellow]not found[/yellow]")


@zp_memory.command("rejected")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def zp_memory_rejected(repo: Path) -> None:
    from zeropath.core.memory import rejected_memories
    from zeropath.core.storage import Storage

    _print_memory_table(rejected_memories(Storage(repo)), "Rejected hypotheses")


@zp_memory.command("consolidate")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
def zp_memory_consolidate(repo: Path) -> None:
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


def _copy_agent_templates(storage) -> None:
    package_dir = Path(__file__).resolve().parents[1]
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


# ---------------------------------------------------------------------------
# MCP (Model Context Protocol) — expose ZeroPath to IDE-side agents
# ---------------------------------------------------------------------------


@cli.group(invoke_without_command=True)
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
    default="all", show_default=True,
    help="Which IDE config to update.",
)
@click.option(
    "--python", default=None,
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
        results = [install_for_client(
            client, python=python, kg_dir=kg, dry_run=dry_run,
        )]

    console = Console()
    table = Table(title="ZeroPath MCP install", show_header=True)
    table.add_column("Client"); table.add_column("Path"); table.add_column("Status")
    for r in results:
        if r.error:
            status = f"[red]error[/red]: {r.error}"
        elif dry_run:
            status = "[yellow]dry-run[/yellow]"
        elif r.already_present:
            status = "[cyan]already present (no change)[/cyan]"
        elif r.written:
            status = "[green]installed[/green]"
        else:
            status = "[red]not written[/red]"
        table.add_row(r.client, str(r.config_path), status)
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
    default="all", show_default=True,
)
@click.pass_context
def mcp_uninstall(ctx: click.Context, client: str) -> None:
    """Remove the ZeroPath MCP entry from one or all IDE configs."""
    from zeropath.mcp_server import SUPPORTED_CLIENTS, uninstall_for_client

    targets = SUPPORTED_CLIENTS if client == "all" else (client,)
    console = Console()
    table = Table(title="ZeroPath MCP uninstall", show_header=True)
    table.add_column("Client"); table.add_column("Path"); table.add_column("Status")
    for c in targets:
        r = uninstall_for_client(c)
        if r.error:
            status = f"[red]error[/red]: {r.error}"
        elif r.written:
            status = "[green]removed[/green]"
        else:
            status = "[yellow]not present[/yellow]"
        table.add_row(c, str(r.config_path), status)
    console.print(table)


@mcp.command("tools")
@click.pass_context
def mcp_tools(ctx: click.Context) -> None:
    """List every tool / resource / prompt exposed by the MCP server."""
    from zeropath.mcp_server import build_default_server

    server = build_default_server(workspace_root=Path("."))
    console = Console()

    table = Table(title="MCP tools", show_header=True)
    table.add_column("Tool"); table.add_column("Description")
    for name, tool in server.tools.items():
        desc = tool.description.replace("\n", " ")
        table.add_row(name, desc[:120])
    console.print(table)

    res_table = Table(title="MCP resources", show_header=True)
    res_table.add_column("URI"); res_table.add_column("Description")
    for uri, r in server.resources.items():
        res_table.add_row(uri, r.description[:120])
    console.print(res_table)

    prompt_table = Table(title="MCP prompts", show_header=True)
    prompt_table.add_column("Name"); prompt_table.add_column("Description")
    for name, p in server.prompts.items():
        prompt_table.add_row(name, p.description[:120])
    console.print(prompt_table)


# ---------------------------------------------------------------------------
# Knowledge graph CLI — Phase 13 corpus ingestion
# ---------------------------------------------------------------------------


@cli.group()
@click.pass_context
def kg(ctx: click.Context) -> None:
    """Manage the Phase 8 knowledge graph (ingest contest corpora, dump, query)."""


def _load_or_init_kg(kg_dir: Optional[Path]):
    """Restore an on-disk KG snapshot or create a fresh in-memory store."""
    from zeropath.knowledge import InMemoryKGStore, KnowledgeGraphOrchestrator
    store = InMemoryKGStore()
    if kg_dir:
        snap = kg_dir / "kg.json"
        if snap.exists():
            try:
                store.restore(snap)
                click.echo(f"[zeropath] restored KG from {snap}", err=True)
            except Exception as exc:
                click.echo(f"[zeropath] failed to restore KG: {exc}", err=True)
    return KnowledgeGraphOrchestrator(store), store


def _persist_kg(store, kg_dir: Optional[Path]) -> Optional[Path]:
    if not kg_dir:
        return None
    kg_dir.mkdir(parents=True, exist_ok=True)
    target = kg_dir / "kg.json"
    store.snapshot(target)
    return target


@kg.command("ingest")
@click.option(
    "--source",
    type=click.Choice(["code4rena", "sherlock", "cantina", "solodit", "spearbit"]),
    required=True,
    help="Which contest corpus to ingest.",
)
@click.option(
    "--kg-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("./kg"), show_default=True,
    help="Directory holding the on-disk KG snapshot.",
)
@click.option(
    "--max", "max_findings", type=int, default=None,
    help="Cap the number of findings ingested from this source.",
)
@click.option(
    "--cache-root", type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Override the corpus cache root (defaults to ~/.zeropath/cache/contest_corpus).",
)
@click.option(
    "--solodit-dump", type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional Solodit JSON dump (use when the public API is unreachable).",
)
@click.option(
    "--cantina-url", multiple=True,
    help="Extra Cantina report URLs to fetch (repeatable).",
)
@click.pass_context
def kg_ingest(
    ctx: click.Context,
    source: str,
    kg_dir: Path,
    max_findings: Optional[int],
    cache_root: Optional[Path],
    solodit_dump: Optional[Path],
    cantina_url: tuple[str, ...],
) -> None:
    """Ingest one contest-platform corpus into the KG."""
    from zeropath.knowledge import (
        ContestCorpusIngestor, IngestionEngine, IntelSource,
    )

    orchestrator, store = _load_or_init_kg(kg_dir)
    engine = IngestionEngine(store, only_actionable=False)
    ingestor = ContestCorpusIngestor(engine, cache_root=cache_root)

    scraper_kwargs: dict[str, Any] = {}
    if source == "solodit" and solodit_dump:
        scraper_kwargs["dump_path"] = solodit_dump
    if source == "cantina" and cantina_url:
        scraper_kwargs["extra_report_urls"] = list(cantina_url)

    click.echo(f"[zeropath] ingesting {source}...", err=True)
    summary = ingestor.ingest(
        IntelSource(source),
        max_findings=max_findings,
        scraper_kwargs=scraper_kwargs,
    )
    persisted = _persist_kg(store, kg_dir)

    console = Console()
    table = Table(title=f"KG ingest — {source}", show_header=True)
    table.add_column("Metric"); table.add_column("Value")
    table.add_row("records parsed", str(summary["records_parsed"]))
    table.add_row("records ingested", str(summary["records_ingested"]))
    table.add_row("errors", str(summary["error_count"]))
    if persisted:
        table.add_row("snapshot", str(persisted))
    console.print(table)
    for err in summary["errors"][:10]:
        click.echo(f"  - {err}", err=True)


@kg.command("seed-all")
@click.option(
    "--kg-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("./kg"), show_default=True,
)
@click.option(
    "--max-per-source", type=int, default=None,
    help="Cap findings ingested per source.",
)
@click.option(
    "--cache-root", type=click.Path(file_okay=False, path_type=Path),
    default=None,
)
@click.option(
    "--skip", multiple=True,
    type=click.Choice(["code4rena", "sherlock", "cantina", "solodit", "spearbit"]),
    help="Skip a specific source (repeatable).",
)
@click.pass_context
def kg_seed_all(
    ctx: click.Context,
    kg_dir: Path,
    max_per_source: Optional[int],
    cache_root: Optional[Path],
    skip: tuple[str, ...],
) -> None:
    """One-shot: ingest every available contest corpus into the KG."""
    from zeropath.knowledge import (
        ContestCorpusIngestor, IngestionEngine, IntelSource,
    )

    orchestrator, store = _load_or_init_kg(kg_dir)
    engine = IngestionEngine(store, only_actionable=False)
    ingestor = ContestCorpusIngestor(engine, cache_root=cache_root)

    sources = [
        s for s in (
            IntelSource.CODE4RENA, IntelSource.SHERLOCK,
            IntelSource.CANTINA, IntelSource.SOLODIT, IntelSource.SPEARBIT,
        )
        if s.value not in skip
    ]
    click.echo(
        f"[zeropath] seed-all over {len(sources)} sources "
        f"(max_per_source={max_per_source or 'unlimited'})",
        err=True,
    )
    report = ingestor.seed_all(sources=sources, max_per_source=max_per_source)
    persisted = _persist_kg(store, kg_dir)

    console = Console()
    table = Table(title="KG seed-all", show_header=True)
    table.add_column("Source"); table.add_column("Parsed")
    table.add_column("Ingested"); table.add_column("Errors")
    for src_name, summary in report.by_source.items():
        table.add_row(
            src_name,
            str(summary["records_parsed"]),
            str(summary["records_ingested"]),
            str(summary["error_count"]),
        )
    console.print(table)
    click.echo(
        f"[zeropath] total ingested: {report.total_records} "
        f"(errors: {report.total_errors})", err=True,
    )
    if persisted:
        click.echo(f"[zeropath] KG snapshot → {persisted}", err=True)


@kg.command("summary")
@click.option(
    "--kg-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("./kg"), show_default=True,
)
@click.pass_context
def kg_summary_cmd(ctx: click.Context, kg_dir: Path) -> None:
    """Print top-level KG stats (exploits, incidents, inferences, accuracy)."""
    orchestrator, store = _load_or_init_kg(kg_dir)
    report = orchestrator.report(protocol_name="all")
    console = Console()
    table = Table(title="KG summary", show_header=True)
    table.add_column("Metric"); table.add_column("Value")
    table.add_row("validated exploits", str(report.exploits_ingested))
    table.add_row("external incidents", str(report.incidents_ingested))
    table.add_row("inferences", str(report.inferences_recorded))
    console.print(table)


def main() -> None:
    """Entry point registered in pyproject.toml."""
    cli(obj={})


if __name__ == "__main__":
    main()
