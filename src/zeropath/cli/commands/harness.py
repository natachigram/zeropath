"""Durable `zeropath harness` campaign commands."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

if not hasattr(click, "Exit"):
    click.Exit = click.exceptions.Exit

console = Console()


@click.group("harness")
def harness() -> None:
    """Run resumable, local-only evidence campaigns."""


@harness.command("init")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--budget", type=click.Choice(["small", "standard", "extended"]), default="standard", show_default=True)
@click.option("--seed", type=int, default=1, show_default=True)
@click.option("--backend", "backends", multiple=True, type=click.Choice(["foundry", "echidna", "medusa", "halmos"]))
@click.option("--scope-path", "scope_paths", multiple=True, help="Explicit source file/directory to freeze; repeatable.")
def harness_init(repo: Path, budget: str, seed: int, backends: tuple[str, ...], scope_paths: tuple[str, ...]) -> None:
    """Freeze source identity and create a resumable harness campaign."""

    from zeropath.harness import HarnessController, HarnessError

    try:
        campaign = HarnessController(repo).initialize(
            budget=budget,
            seed=seed,
            backends=backends or ("foundry",),
            scope_paths=scope_paths or None,
        )
    except (HarnessError, ValueError) as exc:
        console.print(f"[red]Harness init failed:[/red] {exc}")
        raise click.Exit(1)
    console.print(f"[green]Campaign:[/green] {campaign.campaign_id}")
    console.print(f"[green]State:[/green] {Path(campaign.target_root) / '.zeropath' / 'harness' / 'campaigns' / campaign.campaign_id}")
    console.print("Next: zeropath harness run --phase hunt")


@harness.command("status")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--campaign", "campaign_id", default=None)
@click.option("--json", "as_json", is_flag=True, help="Print the complete status JSON.")
def harness_status(repo: Path, campaign_id: str | None, as_json: bool) -> None:
    """Show the current campaign phase, coverage, queue, and backend runs."""

    from zeropath.harness import HarnessController, HarnessError

    try:
        summary = HarnessController(repo).status(campaign_id)
    except HarnessError as exc:
        console.print(f"[red]Harness status unavailable:[/red] {exc}")
        raise click.Exit(1)
    if as_json:
        console.print(json.dumps(summary, indent=2, sort_keys=True))
        return
    campaign = summary.get("campaign")
    if not campaign:
        console.print("[yellow]No harness campaigns found.[/yellow]")
        return
    table = Table(title=f"ZeroPath harness {campaign['campaign_id']}", show_header=True)
    table.add_column("Field")
    table.add_column("Value")
    for key in ("phase", "status", "budget", "access_mode", "source_digest", "active_candidate_id"):
        table.add_row(key, str(campaign.get(key)))
    queue = summary.get("queue", {})
    coverage = summary.get("coverage", {})
    table.add_row("queue items", str(queue.get("items", 0)))
    table.add_row("active queue", ", ".join(queue.get("active", [])) or "none")
    table.add_row("coverage", f"{coverage.get('tested', 0)}/{coverage.get('operations', 0)} tested")
    corpus = summary.get("corpus", {})
    table.add_row("corpus", f"{corpus.get('cases', 0)} portable cases")
    table.add_row("backend runs", str(len(summary.get("backend_runs", []))))
    console.print(table)


@harness.command("run")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--campaign", "campaign_id", default=None, help="Campaign id; defaults to the most recently updated campaign.")
@click.option("--phase", type=click.Choice(["hunt", "bank", "verify", "defend"]), required=True)
@click.option("--candidate", "candidate_id", default=None)
@click.option("--mode", type=click.Choice(["critical", "high-medium", "qa"]), default="critical", show_default=True)
@click.option("--limit", type=int, default=None)
@click.option("--focus", default=None)
@click.option("--backend", type=click.Choice(["foundry", "echidna", "medusa", "halmos"]), default="foundry", show_default=True)
@click.option("--test-path", type=click.Path(path_type=Path), default=None)
@click.option("--write-test-dir", is_flag=True, help="Explicitly write an executable generated test under the target test directory.")
@click.option("--timeout", "timeout_seconds", type=int, default=120, show_default=True)
def harness_run(
    repo: Path,
    campaign_id: str | None,
    phase: str,
    candidate_id: str | None,
    mode: str,
    limit: int | None,
    focus: str | None,
    backend: str,
    test_path: Path | None,
    write_test_dir: bool,
    timeout_seconds: int,
) -> None:
    """Advance exactly one durable campaign phase."""

    from zeropath.harness import HarnessController, HarnessError

    controller = HarnessController(repo)
    try:
        if campaign_id is None:
            latest = controller.status().get("campaign")
            campaign_id = latest.get("campaign_id") if latest else None
        if not campaign_id:
            raise HarnessError("no campaign found; run `zeropath harness init` first")
        if phase == "hunt":
            candidates = controller.hunt(campaign_id, mode=mode, limit=limit, focus=focus)
            console.print(f"[green]Generated {len(candidates)} candidate hypotheses.[/green]")
            for candidate in candidates:
                console.print(f"- {candidate.id}: {candidate.title}")
        elif phase == "bank":
            manifest = controller.bank(campaign_id, candidate_id=candidate_id)
            console.print(f"[green]Active candidate:[/green] {manifest.active_candidate_id or 'none'}")
        elif phase == "verify":
            run = controller.verify(
                campaign_id,
                candidate_id=candidate_id,
                backend=backend,
                test_path=test_path,
                write_test_dir=write_test_dir,
                timeout_seconds=timeout_seconds,
            )
            if run is None:
                console.print("[yellow]Proof artifact prepared; no backend run was executed.[/yellow]")
            else:
                console.print(f"[green]Backend:[/green] {run.backend}  [green]Status:[/green] {run.status}")
                console.print(f"Run: {run.run_id}")
        else:
            result = controller.defend(campaign_id, candidate_id=candidate_id)
            console.print(f"[green]Judge:[/green] {'report-ready pending human review' if result.report_ready else 'needs evidence'}")
            if result.blocking_objections:
                console.print("Blocking objections: " + "; ".join(result.blocking_objections))
    except (HarnessError, ValueError, KeyError) as exc:
        console.print(f"[red]Harness phase failed:[/red] {exc}")
        raise click.Exit(1)


@harness.command("replay")
@click.option("--repo", type=click.Path(file_okay=False, path_type=Path), default=Path("."), show_default=True)
@click.option("--campaign", "campaign_id", required=True)
@click.option("--run", "run_id", required=True)
def harness_replay(repo: Path, campaign_id: str, run_id: str) -> None:
    """Replay one recorded backend run only when the source digest is unchanged."""

    from zeropath.harness import HarnessController, HarnessError

    try:
        result = HarnessController(repo).replay(campaign_id, run_id)
    except (HarnessError, ValueError) as exc:
        console.print(f"[red]Replay refused:[/red] {exc}")
        raise click.Exit(1)
    console.print(f"[green]Replay:[/green] {result.run_id}  [green]Status:[/green] {result.status}")


__all__ = ["harness"]
