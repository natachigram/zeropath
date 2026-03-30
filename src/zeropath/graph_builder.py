"""
Protocol graph construction orchestrator.

Responsibilities:
  - Accept one or more .sol / .vy files (or a directory) as input.
  - Spawn worker processes to parse files in parallel (multiprocessing,
    not threads — bypasses the Python GIL for CPU-bound Slither work).
  - Merge results from all workers into a single ProtocolGraph.
  - Run post-parse passes:
      · IR-based asset flow extraction (needs raw Slither objects)
      · Structural heuristic asset flows (fallback)
      · Version diff analysis (if two graph snapshots are provided)
  - Populate analysis_metadata with statistics.

Design notes:
  - Each worker process runs ContractParser.parse_contract() on one file.
    Workers communicate results back via a multiprocessing Queue.
  - Slither objects are NOT picklable across process boundaries, so only
    model objects (Pydantic, plain dicts) are sent back. IR-based flow
    analysis happens inside the worker and sends back AssetFlow models.
  - Errors in individual files are logged and skipped; the rest of the
    analysis continues (fail-soft per file).
"""

import multiprocessing as mp
import traceback
from pathlib import Path
from typing import Optional

from zeropath.asset_flow import AssetFlowTracker
from zeropath.exceptions import GraphConstructionError, VersionDiffError
from zeropath.logging_config import get_logger
from zeropath.models import ProtocolGraph, VersionDiff
from zeropath.parser import ContractParser, ParseResult

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Worker function (runs in a child process)
# ---------------------------------------------------------------------------


def _parse_worker(
    contract_path: Path,
    solc_version: Optional[str],
    extract_storage: bool,
    detect_proxies: bool,
    result_queue: "mp.Queue[tuple[str, object]]",
) -> None:
    """
    Child-process entry point: parse one contract file and put the result
    (or an error string) on the queue.
    """
    try:
        parser = ContractParser(
            solc_version=solc_version,
            extract_storage=extract_storage,
            detect_proxies=detect_proxies,
        )
        parse_result = parser.parse_contract(contract_path)

        # Run IR-based asset flows inside the worker (Slither objects live here)
        tracker = AssetFlowTracker(use_ir=True)
        ir_flows = tracker.extract_from_slither(
            parse_result.slither_contracts,
            parse_result.function_id_map,
        )
        parse_result.slither_contracts = []  # drop non-picklable objects

        result_queue.put(("ok", (parse_result, ir_flows)))

    except Exception as exc:
        tb = traceback.format_exc()
        result_queue.put(("error", (str(contract_path), str(exc), tb)))


# ---------------------------------------------------------------------------
# ProtocolGraphBuilder
# ---------------------------------------------------------------------------


class ProtocolGraphBuilder:
    """
    Orchestrates the construction of a complete ProtocolGraph.

    Args:
        solc_version:     Pin solc version (None = auto-detect per file).
        extract_storage:  Compute storage slot layouts.
        extract_flows:    Run asset flow analysis.
        detect_proxies:   Detect proxy patterns.
        max_workers:      Number of parallel worker processes (default: CPU count).
    """

    def __init__(
        self,
        solc_version: Optional[str] = None,
        extract_storage: bool = True,
        extract_flows: bool = True,
        detect_proxies: bool = True,
        max_workers: Optional[int] = None,
    ) -> None:
        self.solc_version = solc_version
        self.extract_storage = extract_storage
        self.extract_flows = extract_flows
        self.detect_proxies = detect_proxies
        self.max_workers = max_workers or max(1, mp.cpu_count() - 1)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_from_files(self, contract_paths: list[Path]) -> ProtocolGraph:
        """
        Build a protocol graph from an explicit list of .sol / .vy files.

        Files that fail to parse are logged and skipped.

        Args:
            contract_paths: List of paths to contract source files.

        Returns:
            Merged ProtocolGraph.

        Raises:
            GraphConstructionError: If all files fail or assembly itself fails.
        """
        if not contract_paths:
            raise GraphConstructionError("No contract files provided.")

        logger.info(
            "building_protocol_graph",
            num_files=len(contract_paths),
            max_workers=self.max_workers,
        )

        parse_results, ir_flows_all, errors = self._parallel_parse(contract_paths)

        if not parse_results and errors:
            details = "; ".join(f"{p}: {e}" for p, e, _ in errors)
            raise GraphConstructionError(f"All files failed to parse: {details}")

        for path, err, _ in errors:
            logger.warning("file_parse_failed", path=path, error=err)

        return self._assemble(parse_results, ir_flows_all)

    def build_from_directory(
        self,
        directory: Path,
        recursive: bool = True,
    ) -> ProtocolGraph:
        """
        Build a protocol graph from all contracts found in a directory.

        Args:
            directory: Root directory to scan.
            recursive: Also scan subdirectories.

        Returns:
            Merged ProtocolGraph.

        Raises:
            GraphConstructionError: If no .sol / .vy files are found.
        """
        pattern = "**/*" if recursive else "*"
        contract_files = [
            p
            for p in directory.glob(pattern)
            if p.suffix in (".sol", ".vy") and p.is_file()
        ]

        if not contract_files:
            raise GraphConstructionError(
                f"No .sol or .vy files found in {directory}"
            )

        logger.info(
            "scanning_directory",
            directory=str(directory),
            count=len(contract_files),
        )
        return self.build_from_files(contract_files)

    def build_version_diff(
        self,
        paths_v1: list[Path],
        paths_v2: list[Path],
    ) -> ProtocolGraph:
        """
        Analyse two versions of a protocol and produce a diff graph.

        The returned ProtocolGraph represents v2, with a VersionDiff field
        describing changes from v1.

        Args:
            paths_v1: Contract files for version 1 (baseline).
            paths_v2: Contract files for version 2 (new version).

        Returns:
            ProtocolGraph of v2 with .version_diff populated.

        Raises:
            VersionDiffError: If either version fails to build.
        """
        try:
            graph_v1 = self.build_from_files(paths_v1)
            graph_v2 = self.build_from_files(paths_v2)
        except Exception as exc:
            raise VersionDiffError(f"Version diff build failed: {exc}") from exc

        graph_v2.version_diff = _compute_diff(graph_v1, graph_v2)
        logger.info(
            "version_diff_computed",
            added_contracts=len(graph_v2.version_diff.added_contracts),
            removed_contracts=len(graph_v2.version_diff.removed_contracts),
            added_functions=len(graph_v2.version_diff.added_functions),
            modified_functions=len(graph_v2.version_diff.modified_functions),
        )
        return graph_v2

    # ------------------------------------------------------------------
    # Parallel parsing
    # ------------------------------------------------------------------

    def _parallel_parse(
        self,
        contract_paths: list[Path],
    ) -> tuple[list[ParseResult], list, list]:
        """
        Dispatch parsing to worker processes and collect results.

        Returns:
            (parse_results, ir_flows_all, errors)
        """
        ctx = mp.get_context("spawn")
        result_queue: mp.Queue = ctx.Queue()
        parse_results: list[ParseResult] = []
        ir_flows_all = []
        errors: list[tuple[str, str, str]] = []

        active: list[mp.Process] = []

        def _drain_queue() -> None:
            while not result_queue.empty():
                status, payload = result_queue.get_nowait()
                if status == "ok":
                    pr, flows = payload
                    parse_results.append(pr)
                    ir_flows_all.extend(flows)
                else:
                    errors.append(payload)

        for i, path in enumerate(contract_paths):
            # Throttle: wait for a slot if at capacity
            while len(active) >= self.max_workers:
                active = [p for p in active if p.is_alive()]
                _drain_queue()

            proc = ctx.Process(
                target=_parse_worker,
                args=(
                    path,
                    self.solc_version,
                    self.extract_storage,
                    self.detect_proxies,
                    result_queue,
                ),
                daemon=True,
            )
            proc.start()
            active.append(proc)
            logger.debug("worker_started", file=path.name, pid=proc.pid)

        # Wait for remaining workers
        for proc in active:
            proc.join(timeout=120)
            if proc.is_alive():
                logger.warning("worker_timeout", pid=proc.pid)
                proc.terminate()

        _drain_queue()

        # Final drain (join may finish before queue is fully written)
        while not result_queue.empty():
            status, payload = result_queue.get()
            if status == "ok":
                pr, flows = payload
                parse_results.append(pr)
                ir_flows_all.extend(flows)
            else:
                errors.append(payload)

        return parse_results, ir_flows_all, errors

    # ------------------------------------------------------------------
    # Graph assembly
    # ------------------------------------------------------------------

    def _assemble(
        self,
        parse_results: list[ParseResult],
        ir_flows: list,
    ) -> ProtocolGraph:
        """Merge all ParseResults into a single ProtocolGraph."""
        try:
            graph = ProtocolGraph()

            for pr in parse_results:
                graph.contracts.extend(pr.contracts)
                graph.functions.extend(pr.functions)
                graph.state_variables.extend(pr.state_variables)
                graph.function_calls.extend(pr.function_calls)
                graph.events.extend(pr.events)
                graph.proxy_relationships.extend(pr.proxy_relationships)

                # Merge external dependencies (deduplicate by name)
                existing_dep_names = {d.name for d in graph.external_dependencies}
                for dep in pr.external_dependencies:
                    if dep.name not in existing_dep_names:
                        graph.external_dependencies.append(dep)
                        existing_dep_names.add(dep.name)
                    else:
                        # Merge call sites into existing dep
                        existing = next(
                            d for d in graph.external_dependencies if d.name == dep.name
                        )
                        for ref in dep.references:
                            if ref not in existing.references:
                                existing.references.append(ref)
                        for cs in dep.call_sites:
                            if cs not in existing.call_sites:
                                existing.call_sites.append(cs)

            # IR-based flows (highest precision)
            if self.extract_flows and ir_flows:
                graph.asset_flows.extend(ir_flows)

            # Structural heuristic flows (fallback / supplement)
            if self.extract_flows:
                heuristic_flows = AssetFlowTracker.extract_from_models(
                    graph.functions,
                    graph.function_calls,
                )
                # Add only flows not already captured by IR
                ir_keys = {
                    (f.from_function_id, f.to_function_id, f.asset_type)
                    for f in graph.asset_flows
                }
                for flow in heuristic_flows:
                    key = (flow.from_function_id, flow.to_function_id, flow.asset_type)
                    if key not in ir_keys:
                        graph.asset_flows.append(flow)

            # Propagate source_available: False if ANY file was bytecode-only
            graph.source_available = all(pr.source_available for pr in parse_results)

            graph.analysis_metadata = {
                "num_contracts": len(graph.contracts),
                "num_functions": len(graph.functions),
                "num_state_variables": len(graph.state_variables),
                "num_events": len(graph.events),
                "call_graph_edges": len(graph.function_calls),
                "asset_flows": len(graph.asset_flows),
                "external_dependencies": len(graph.external_dependencies),
                "proxy_relationships": len(graph.proxy_relationships),
                "proxy_contracts": [
                    c.name
                    for c in graph.contracts
                    if c.proxy_type.value != "none"
                ],
                "languages": list(
                    {c.language.value for c in graph.contracts}
                ),
                "source_available": graph.source_available,
                "bytecode_only_contracts": [
                    c.name
                    for pr in parse_results
                    if not pr.source_available
                    for c in pr.contracts
                ],
            }

            logger.info(
                "protocol_graph_assembled",
                **{k: v for k, v in graph.analysis_metadata.items()
                   if not isinstance(v, list)},
            )
            return graph

        except Exception as exc:
            logger.error("graph_assembly_failed", error=str(exc))
            raise GraphConstructionError(f"Graph assembly failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Version diff computation
# ---------------------------------------------------------------------------


def _compute_diff(graph_v1: ProtocolGraph, graph_v2: ProtocolGraph) -> VersionDiff:
    """Compare two ProtocolGraphs and return a VersionDiff."""
    names_v1_contracts = {c.name for c in graph_v1.contracts}
    names_v2_contracts = {c.name for c in graph_v2.contracts}

    added_contracts = sorted(names_v2_contracts - names_v1_contracts)
    removed_contracts = sorted(names_v1_contracts - names_v2_contracts)

    # Function comparison by "ContractName.functionName" signature
    def func_keys(graph: ProtocolGraph) -> dict[str, str]:
        contract_map = {c.id: c.name for c in graph.contracts}
        return {
            f"{contract_map.get(f.contract_id, '?')}.{f.name}": f.signature.selector or ""
            for f in graph.functions
        }

    funcs_v1 = func_keys(graph_v1)
    funcs_v2 = func_keys(graph_v2)

    added_functions = sorted(set(funcs_v2) - set(funcs_v1))
    removed_functions = sorted(set(funcs_v1) - set(funcs_v2))
    # Modified = same name but different selector (signature changed)
    modified_functions = sorted(
        k for k in set(funcs_v1) & set(funcs_v2) if funcs_v1[k] != funcs_v2[k]
    )

    # State variable comparison
    var_names_v1 = {f"{v.contract_id}.{v.name}" for v in graph_v1.state_variables}
    var_names_v2 = {f"{v.contract_id}.{v.name}" for v in graph_v2.state_variables}
    added_vars = sorted(var_names_v2 - var_names_v1)
    removed_vars = sorted(var_names_v1 - var_names_v2)

    dep_names_v1 = {d.name for d in graph_v1.external_dependencies}
    dep_names_v2 = {d.name for d in graph_v2.external_dependencies}
    new_deps = sorted(dep_names_v2 - dep_names_v1)

    # Attack surface delta heuristic
    critical_signals = [
        bool(added_functions),          # new functions = new attack surface
        bool(new_deps),                 # new external dependencies = new trust assumptions
        len(added_contracts) > 0,       # new contracts
    ]
    medium_signals = [
        bool(modified_functions),       # changed function signatures
        bool(removed_vars),             # removed state vars (storage layout change)
    ]

    if sum(critical_signals) >= 2:
        delta = "high"
    elif any(critical_signals):
        delta = "medium"
    elif any(medium_signals):
        delta = "low"
    else:
        delta = "minimal"

    return VersionDiff(
        added_contracts=added_contracts,
        removed_contracts=removed_contracts,
        added_functions=added_functions,
        removed_functions=removed_functions,
        modified_functions=modified_functions,
        added_state_vars=added_vars,
        removed_state_vars=removed_vars,
        new_external_deps=new_deps,
        attack_surface_delta=delta,
    )
