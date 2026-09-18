"""Campaign controller for the durable ZeroPath security harness.

This module is the application layer between the existing evidence-first core
and replaceable execution backends.  It implements a small explicit state
machine, Hunt-compatible artifacts, and one expensive verification slot.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Iterable

from zeropath.adapters.evm import EVMAdapter
from zeropath.adapters.evm.foundry import write_candidate_test, write_runnable_poc
from zeropath.core.candidates import generate_candidates
from zeropath.core.judge import judge_candidate
from zeropath.core.state_plan import get_or_build_candidate_state_plan
from zeropath.core.storage import Storage
from zeropath.core.utils import repo_commit, utc_now
from zeropath.harness.backends import (
    BackendContext,
    backend_availability,
    run_named_backend,
    supported_backends,
)
from zeropath.harness.corpus import generate_cases
from zeropath.harness.digests import json_digest, scoped_source_digest, sha256_bytes
from zeropath.harness.models import (
    BackendRun,
    HarnessActor,
    HarnessCheckpoint,
    HarnessCoverage,
    HarnessManifest,
    HarnessMetrics,
    HarnessOperation,
    HarnessQueue,
    HarnessQueueItem,
)
from zeropath.harness.store import HarnessStateError, HarnessStore


class HarnessError(RuntimeError):
    """Raised when a campaign cannot advance without user action."""


_PHASE_TRANSITIONS: dict[str, set[str]] = {
    "frame": {"hunt", "paused"},
    "hunt": {"bank", "paused"},
    "bank": {"verify", "paused"},
    "verify": {"defend", "bank", "paused"},
    "defend": {"complete", "bank", "paused"},
    "paused": {"hunt", "bank", "verify", "defend", "complete"},
    "complete": set(),
}


class HarnessController:
    """Own campaign transitions while delegating execution to backend ports."""

    def __init__(self, root_path: str | Path = ".") -> None:
        self.root_path = Path(root_path).resolve()
        self.storage = Storage(self.root_path)
        self.store = HarnessStore(self.root_path)

    # ------------------------------------------------------------------
    # Frame
    # ------------------------------------------------------------------

    def initialize(
        self,
        *,
        budget: str = "standard",
        seed: int = 1,
        backends: Iterable[str] = ("foundry",),
        scope_paths: Iterable[str] | None = None,
    ) -> HarnessManifest:
        """Create a new local-only campaign and freeze its source identity."""

        self.storage.require_initialized()
        config = self.storage.load_project_config()
        index = self.storage.load_record("ingest", "evm_index") or {}
        requested_backends = list(dict.fromkeys(item.strip().lower() for item in backends if item.strip()))
        if not requested_backends:
            requested_backends = ["foundry"]
        unknown = sorted(set(requested_backends) - set(supported_backends()))
        if unknown:
            raise HarnessError(f"unsupported backend(s): {', '.join(unknown)}")
        if budget not in {"small", "standard", "extended"}:
            raise HarnessError("budget must be small, standard, or extended")
        if seed < 0:
            raise HarnessError("seed must be non-negative")

        explicit_scope = scope_paths is not None
        source_paths = list(scope_paths or config.source_paths or [
            item.get("path", "") for item in index.get("files", []) if item.get("path")
        ])
        if not explicit_scope:
            source_paths = _production_paths(source_paths)
        if not source_paths:
            raise HarnessError("no source paths were found; frame an explicit source scope first")
        source_digest, expanded_paths, missing_paths = scoped_source_digest(
            self.root_path,
            source_paths,
        )
        if not expanded_paths:
            missing = ", ".join(missing_paths) or "empty scope"
            raise HarnessError(f"no readable source files were found in the requested scope: {missing}")
        commit = repo_commit(self.root_path)
        audited_ref_type = "git_commit" if commit else "source_tree"
        campaign_id = self._new_campaign_id()
        toolchain = _toolchain_snapshot(self.root_path, requested_backends)
        limits = _limits_for_budget(budget)
        operations = _build_operations(index, self.storage.load_protocol_intent())
        scope_text = _scope_document(config, campaign_id, expanded_paths, missing_paths, commit)
        frame_facts = _frame_facts_document(config, index, requested_backends, source_digest)
        baseline = {
            "schema_version": 1,
            "audited_ref_type": audited_ref_type,
            "audited_commit": commit,
            "source_paths": expanded_paths,
            "missing_source_paths": missing_paths,
            "source_digest": source_digest,
            "worktree_status": _git_status(self.root_path),
            "python": sys.version,
            "toolchain": toolchain,
            "access_mode": "local-only",
            "production_mutation": False,
        }
        reference_lock = {
            "schema_version": 1,
            "status": "best_effort",
            "mode": "quick",
            "approved_by": "user task",
            "audited_ref_type": audited_ref_type,
            "audited_commit": commit,
            "source_paths": expanded_paths,
            "source_digest": source_digest,
            "engagement": {
                "access_mode": "local-only",
                "public_chain_writes": False,
                "real_funds_or_users": False,
            },
            "frozen_rules": [
                "target_form_and_source_identity",
                "local_only_execution",
                "no_public_chain_writes",
                "no_real_funds_or_users",
                "human_review_before_reporting",
            ],
            "files": [],
        }
        reference_files = {
            "scope.md": scope_text,
            "frame-facts.md": frame_facts,
            "baseline.json": baseline,
        }

        def artifact_bytes(path: str, content: Any) -> bytes:
            if path.endswith(".json"):
                return (json.dumps(content, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
                    "utf-8"
                )
            return str(content).encode("utf-8")

        reference_lock["files"] = [
            {
                "path": path,
                "owner": "harness-frame",
                "required": True,
                "sha256": sha256_bytes(artifact_bytes(path, content)),
            }
            for path, content in reference_files.items()
        ]
        reference_lock_digest = json_digest(reference_lock)
        phase_limits = dict(limits)
        phase_limits["missing_source_paths"] = missing_paths
        phase_limits["max_corpus_cases"] = _corpus_limits(budget)[0]
        phase_limits["max_sequence_depth"] = _corpus_limits(budget)[1]
        manifest = HarnessManifest(
            campaign_id=campaign_id,
            project_id=config.project_id,
            target_root=str(self.root_path),
            task="new-hunt",
            engagement_mode="quick",
            budget=budget,  # type: ignore[arg-type]
            access_mode="local-only",
            status="active",
            phase="frame",
            audited_ref_type=audited_ref_type,  # type: ignore[arg-type]
            audited_commit=commit,
            source_paths=expanded_paths,
            source_digest=source_digest,
            scope_digest=sha256_bytes(scope_text.encode("utf-8")),
            reference_lock_digest=reference_lock_digest,
            backends=requested_backends,
            seed=seed,
            limits=phase_limits,
            actors=[
                HarnessActor(
                    id="attacker",
                    trust="untrusted",
                    source="local fixture label",
                    capabilities=["permissionless entrypoints only"],
                ),
                HarnessActor(
                    id="victim",
                    trust="untrusted",
                    source="local fixture label",
                    capabilities=["receives only synthetic value"],
                ),
            ],
            toolchain=toolchain,
            checkpoint=HarnessCheckpoint(
                status="complete",
                last_completed="frame",
                last_observation="Source identity, local-only boundary, and operation coverage were frozen.",
                result_class="advanced",
                next_action="Run `zeropath harness run --phase hunt` to generate bounded hypotheses.",
            ),
        )
        coverage = HarnessCoverage(
            source_digest=source_digest,
            reference_lock_digest=reference_lock_digest,
            operations=operations,
        )
        queue = HarnessQueue(
            audited_commit=commit,
            reference_lock_digest=reference_lock_digest,
            items=[
                _queue_item_for_candidate(candidate, discovery_stream="merged")
                for candidate in self.storage.list_candidates()
            ],
        )
        metrics = HarnessMetrics(
            counters={
                "raw_leads": 0,
                "admitted_leads": 0,
                "deep_verifications": 0,
                "late_kills": 0,
                "poc_attempts": 0,
                "clean_reproductions": 0,
                "submit_ready": 0,
                "duplicates": 0,
                "human_rejected": 0,
            },
            precision={
                "bucket_a_cards": 0,
                "bucket_b_cards": 0,
                "bucket_c_kills": 0,
                "pre_poc_kills": 0,
                "scope_or_trust_kills": 0,
                "paid_floor_kills": 0,
            },
            quality={"discovery_pulses": 0, "unique_cards": 0, "state_repairs": 0},
            notes=[
                "Metrics route workflow quality; they never certify target safety.",
                "Reference status is best_effort until a human supplies program scope.",
            ],
        )
        text_files = {
            "scope.md": scope_text,
            "frame-facts.md": frame_facts,
            "decisions.md": (
                "# Harness decisions\n\n"
                "- The campaign is local-only and best-effort.\n"
                "- Source identity is pinned before discovery.\n"
                "- One expensive verification item is active at a time.\n"
                "- Generated artifacts route work; executable evidence and human review decide claims.\n"
            ),
            "followups.md": "# Focused follow-ups\n\nNo follow-ups recorded yet.\n",
            "handoff.md": (
                "# Harness handoff\n\n"
                f"Campaign `{campaign_id}` is framed and ready for discovery.\n"
                "\nNext action: run the Hunt phase.\n"
            ),
        }
        self.store.create_campaign(
            manifest,
            text_files=text_files,
            json_files={
                "baseline.json": baseline,
                "reference-lock.json": reference_lock,
                "coverage.json": coverage,
                "attack-surface.json": queue,
                "metrics.json": metrics,
            },
        )
        corpus_cases = generate_cases(
            [operation.id for operation in operations],
            seed=seed,
            count=phase_limits["max_corpus_cases"],
            depth=phase_limits["max_sequence_depth"],
        )
        for case in corpus_cases:
            self.store.save_corpus_case(case, campaign_id)
        self.store.append_event(
            campaign_id,
            "corpus.generated",
            "frame",
            {"case_ids": [case.case_id for case in corpus_cases]},
        )
        return manifest

    # ------------------------------------------------------------------
    # Hunt / bank
    # ------------------------------------------------------------------

    def hunt(
        self,
        campaign_id: str,
        *,
        mode: str = "critical",
        limit: int | None = None,
        focus: str | None = None,
    ) -> list[Any]:
        manifest = self._load(campaign_id)
        if manifest.phase not in {"frame", "hunt", "paused"}:
            raise HarnessError(f"campaign phase {manifest.phase!r} cannot start hunt")
        self._begin(manifest, "hunt", f"zeropath harness run --phase hunt --campaign {campaign_id}")
        max_cards = int(limit or manifest.limits.get("max_cards", 4))
        candidates = generate_candidates(
            self.storage,
            mode=mode,
            limit=max_cards,
            focus=focus,
        )
        queue = self.store.load_queue(campaign_id)
        metrics = self.store.load_metrics(campaign_id)
        known = {item.id for item in queue.items}
        for candidate in candidates:
            if candidate.id in known:
                continue
            item = _queue_item_for_candidate(candidate)
            queue.items.append(item)
            known.add(candidate.id)
            metrics.counters["raw_leads"] = metrics.counters.get("raw_leads", 0) + 1
            metrics.quality["unique_cards"] = metrics.quality.get("unique_cards", 0) + 1
            if item.precision_bucket == "B":
                metrics.precision["bucket_b_cards"] = metrics.precision.get("bucket_b_cards", 0) + 1
            else:
                metrics.precision["bucket_c_kills"] = metrics.precision.get("bucket_c_kills", 0) + 1
        metrics.quality["discovery_pulses"] = metrics.quality.get("discovery_pulses", 0) + 1
        self.store.save_queue(queue, campaign_id)
        self.store.save_metrics(metrics, campaign_id)
        self._complete(
            manifest,
            next_phase="bank",
            observation=f"Generated {len(candidates)} new candidate hypotheses.",
            next_action="Select one candidate with `zeropath harness run --phase bank --candidate ZP-…`.",
            event_type="discovery.completed",
            payload={"candidate_ids": [candidate.id for candidate in candidates]},
        )
        return candidates

    def bank(self, campaign_id: str, *, candidate_id: str | None = None) -> HarnessManifest:
        manifest = self._load(campaign_id)
        if manifest.phase not in {"bank", "paused"}:
            raise HarnessError(f"campaign phase {manifest.phase!r} cannot start bank")
        self._begin(manifest, "bank", f"zeropath harness run --phase bank --campaign {campaign_id}")
        queue = self.store.load_queue(campaign_id)
        candidate_item = None
        if candidate_id:
            candidate_item = next((item for item in queue.items if item.id == candidate_id), None)
            if candidate_item is None:
                raise HarnessError(f"candidate {candidate_id} is not in the campaign queue")
        else:
            candidate_item = next((item for item in queue.items if item.status == "candidate"), None)
        if candidate_item is None:
            self._pause(
                manifest,
                observation="No admitted candidate is available for deep verification.",
                next_action="Run the Hunt phase or provide --candidate for a queued hypothesis.",
                event_type="bank.blocked",
            )
            return manifest
        if candidate_item.precision_bucket == "C":
            self._pause(
                manifest,
                observation=f"Candidate {candidate_item.id} was killed by the pre-PoC precision gate.",
                next_action="Reopen only with new source, scope, deployment, or executable evidence.",
                event_type="bank.killed_precision_gate",
                result_class="falsified",
            )
            raise HarnessError(f"candidate {candidate_item.id} is a precision-gate C kill")
        used_cycles = int(manifest.limits.get("deep_cycles_used", 0))
        max_cycles = int(manifest.limits.get("max_deep_cycles", 1))
        if used_cycles >= max_cycles:
            self._pause(
                manifest,
                observation="The declared deep-verification budget is exhausted.",
                next_action="Start a new campaign or explicitly increase the budget.",
                event_type="bank.budget_exhausted",
                result_class="blocked",
            )
            raise HarnessError("deep-verification budget exhausted")
        for item in queue.items:
            if item.id != candidate_item.id and item.status == "active":
                item.status = "candidate"
        candidate_item.status = "active"
        self.store.save_queue(queue, campaign_id)
        manifest.active_candidate_id = candidate_item.id
        manifest.active_hypothesis = candidate_item.hypothesis
        manifest.limits["deep_cycles_used"] = int(manifest.limits.get("deep_cycles_used", 0)) + 1
        self._complete(
            manifest,
            next_phase="verify",
            observation=f"Admitted {candidate_item.id} as the single active deep hypothesis.",
            next_action=(
                f"Run `zeropath harness run --phase verify --candidate {candidate_item.id}`."
            ),
            event_type="bank.selected",
            payload={"candidate_id": candidate_item.id, "precision_bucket": candidate_item.precision_bucket},
        )
        return manifest

    # ------------------------------------------------------------------
    # Verify / defend
    # ------------------------------------------------------------------

    def verify(
        self,
        campaign_id: str,
        *,
        candidate_id: str | None = None,
        backend: str = "foundry",
        test_path: str | Path | None = None,
        generate_poc: bool = True,
        write_test_dir: bool = False,
        timeout_seconds: int = 120,
    ) -> BackendRun | None:
        manifest = self._load(campaign_id)
        candidate_id = candidate_id or manifest.active_candidate_id
        if not candidate_id:
            raise HarnessError("verify requires --candidate or an active banked candidate")
        candidate = self.storage.load_candidate(candidate_id)
        if candidate is None:
            raise HarnessError(f"candidate not found: {candidate_id}")
        if not manifest.active_candidate_id:
            raise HarnessError("verify requires a candidate selected by the bank phase")
        if candidate_id != manifest.active_candidate_id:
            raise HarnessError(
                f"candidate {candidate_id} is not the single active hypothesis "
                f"({manifest.active_candidate_id})"
            )
        if manifest.phase not in {"verify", "paused"}:
            raise HarnessError(f"campaign phase {manifest.phase!r} cannot start verify")
        backend = backend.strip().lower()
        if backend not in supported_backends():
            raise HarnessError(f"unsupported backend: {backend}")
        if backend not in manifest.backends:
            raise HarnessError(
                f"backend {backend!r} was not framed for this campaign; "
                f"choose one of: {', '.join(manifest.backends)}"
            )
        self._begin(
            manifest,
            "verify",
            f"zeropath harness run --phase verify --campaign {campaign_id} --candidate {candidate_id}",
        )
        current_digest, _, _ = scoped_source_digest(self.root_path, manifest.source_paths)
        if current_digest != manifest.source_digest:
            self._pause(
                manifest,
                observation="Scoped source digest changed after frame; evidence cannot be reused.",
                next_action="Start a new campaign or explicitly re-frame after reviewing the drift.",
                event_type="verify.blocked_source_drift",
                result_class="blocked",
            )
            raise HarnessError("scoped source drift detected; campaign is paused")

        runnable_path = Path(test_path) if test_path else None
        generator = None
        if generate_poc:
            runnable_path, generator = self._prepare_candidate_poc(
                manifest,
                candidate,
                write_test_dir=write_test_dir,
                requested_test_path=runnable_path,
            )
        if runnable_path is None:
            self._pause(
                manifest,
                observation="PoC artifact prepared but no executable test path was supplied.",
                next_action="Provide --test-path or re-run with --write-test-dir.",
                event_type="verify.awaiting_test_path",
            )
            return None

        metrics = self.store.load_metrics(campaign_id)
        metrics.counters["deep_verifications"] = metrics.counters.get("deep_verifications", 0) + 1
        metrics.counters["poc_attempts"] = metrics.counters.get("poc_attempts", 0) + 1
        self.store.save_metrics(metrics, campaign_id)
        context = BackendContext(
            campaign_id=campaign_id,
            root_path=self.root_path,
            target_path=runnable_path,
            seed=manifest.seed,
            timeout_seconds=max(1, timeout_seconds),
            verbosity=generator.verbosity if generator is not None and backend == "foundry" else 0,
        )
        run = run_named_backend(
            backend,
            context,
            source_digest_before=manifest.source_digest,
        )
        run_path = self.store.save_backend_run(run)
        run.evidence_path = str(run_path)
        self.store.save_backend_run(run)
        source_after, _, _ = scoped_source_digest(self.root_path, manifest.source_paths)
        run.source_digest_after = source_after
        if source_after != manifest.source_digest:
            run.status = "blocked"
            run.error = (
                "scoped source digest changed while the backend ran; "
                "the backend observation is not reusable as proof"
            )
        self.store.save_backend_run(run)
        if run.status == "blocked":
            self._pause(
                manifest,
                observation=run.error or "backend changed the frozen source scope",
                next_action="Start a new campaign or remove generated files from the frozen scope.",
                event_type="verify.blocked_source_drift",
                result_class="blocked",
            )
            return run
        self._apply_backend_evidence(candidate, run, generator)
        self.storage.save_candidate(candidate)
        self._update_coverage_for_candidate(campaign_id, candidate, run)
        queue = self.store.load_queue(campaign_id)
        item = next((entry for entry in queue.items if entry.id == candidate.id), None)
        if item:
            item.evidence.append(str(run_path))
            item.status = "proven" if run.status == "passed" and candidate.impact.measured else "active"
            item.reality_anchor = str(run_path)
        self.store.save_queue(queue, campaign_id)
        next_phase = "defend" if run.status == "passed" else "paused"
        next_action = (
            f"Run `zeropath harness run --phase defend --candidate {candidate.id}`."
            if next_phase == "defend"
            else "Inspect the backend evidence, fix the harness/test, or provide a different proof path."
        )
        if next_phase == "defend":
            self._complete(
                manifest,
                next_phase="defend",
                observation=f"{backend} returned {run.status}; executable evidence was recorded.",
                next_action=next_action,
                event_type="verify.completed",
                payload={"candidate_id": candidate.id, "run_id": run.run_id, "status": run.status},
            )
        else:
            self._pause(
                manifest,
                observation=f"{backend} returned {run.status}; no report-ready claim was made.",
                next_action=next_action,
                event_type="verify.needs_evidence",
                result_class="falsified" if run.status == "failed" else "operational-failure",
            )
        return run

    def defend(self, campaign_id: str, *, candidate_id: str | None = None) -> Any:
        manifest = self._load(campaign_id)
        candidate_id = candidate_id or manifest.active_candidate_id
        if not candidate_id:
            raise HarnessError("defend requires --candidate or an active candidate")
        candidate = self.storage.load_candidate(candidate_id)
        if candidate is None:
            raise HarnessError(f"candidate not found: {candidate_id}")
        if not manifest.active_candidate_id:
            raise HarnessError("defend requires a candidate selected by the bank phase")
        if candidate_id != manifest.active_candidate_id:
            raise HarnessError(
                f"candidate {candidate_id} is not the single active hypothesis "
                f"({manifest.active_candidate_id})"
            )
        if manifest.phase not in {"defend", "paused"}:
            raise HarnessError(f"campaign phase {manifest.phase!r} cannot start defend")
        self._begin(
            manifest,
            "defend",
            f"zeropath harness run --phase defend --campaign {campaign_id} --candidate {candidate_id}",
        )
        result = judge_candidate(candidate, self.storage)
        self.store.write_json(
            campaign_id,
            Path("evidence") / f"{candidate.id.replace('-', '_')}_judge.json",
            result,
            overwrite=True,
        )
        metrics = self.store.load_metrics(campaign_id)
        if result.report_ready:
            metrics.counters["submit_ready"] = metrics.counters.get("submit_ready", 0) + 1
        else:
            metrics.counters["human_rejected"] = metrics.counters.get("human_rejected", 0) + 1
        self.store.save_metrics(metrics, campaign_id)
        handoff = _handoff_document(manifest, candidate, result)
        self.store.write_text(campaign_id, "handoff.md", handoff, overwrite=True)
        next_phase = "complete" if result.report_ready else "paused"
        if result.report_ready:
            self._complete(
                manifest,
                next_phase="complete",
                observation="Judge returned report_ready=true; human review remains required.",
                next_action="Human review and explicit report export are still required.",
                event_type="defend.submit_ready_pending_human",
                payload={"candidate_id": candidate.id, "severity": result.severity},
            )
        else:
            self._pause(
                manifest,
                observation="Judge recorded objections or missing evidence.",
                next_action="Resolve the listed objections, then re-run verify/defend.",
                event_type="defend.needs_evidence",
            )
        return result

    # ------------------------------------------------------------------
    # Replay / status
    # ------------------------------------------------------------------

    def replay(self, campaign_id: str, run_id: str) -> BackendRun:
        manifest = self._load(campaign_id)
        run = self.store.load_backend_run(campaign_id, run_id)
        current_digest, _, _ = scoped_source_digest(self.root_path, manifest.source_paths)
        if current_digest != run.source_digest_before or current_digest != manifest.source_digest:
            self._pause(
                manifest,
                observation="Replay refused because the frozen source digest no longer matches.",
                next_action="Start a new campaign after reviewing source drift.",
                event_type="replay.blocked_source_drift",
                result_class="blocked",
            )
            raise HarnessError("replay refused: source digest drift")
        context = BackendContext(
            campaign_id=campaign_id,
            root_path=self.root_path,
            target_path=run.target_path,
            seed=run.seed if run.seed is not None else manifest.seed,
            timeout_seconds=max(1, run.timeout_seconds),
            verbosity=run.verbosity,
            replay_of=run.run_id,
        )
        replayed = run_named_backend(
            run.backend,
            context,
            source_digest_before=current_digest,
        )
        replayed_path = self.store.save_backend_run(replayed)
        replayed.evidence_path = str(replayed_path)
        source_after, _, _ = scoped_source_digest(self.root_path, manifest.source_paths)
        replayed.source_digest_after = source_after
        if source_after != current_digest:
            replayed.status = "blocked"
            replayed.error = (
                "scoped source digest changed while replaying; "
                "the replay receipt is not reusable as proof"
            )
        self.store.save_backend_run(replayed)
        self.store.append_event(
            campaign_id,
            "replay.completed",
            manifest.phase,
            {"original_run_id": run_id, "replay_run_id": replayed.run_id, "status": replayed.status},
        )
        return replayed

    def status(self, campaign_id: str | None = None) -> dict[str, Any]:
        manifest = self._load(campaign_id) if campaign_id else self.store.latest_campaign()
        if manifest is None:
            return {"campaign": None, "campaigns": 0}
        queue = self.store.load_queue(manifest.campaign_id)
        coverage = self.store.load_coverage(manifest.campaign_id)
        runs = self.store.list_backend_runs(manifest.campaign_id)
        corpus = self.store.list_corpus_cases(manifest.campaign_id)
        return {
            "campaign": manifest.model_dump(mode="json"),
            "queue": {
                "items": len(queue.items),
                "active": [item.id for item in queue.items if item.status == "active"],
            },
            "coverage": {
                "operations": len(coverage.operations),
                "tested": sum(1 for item in coverage.operations if item.outcome == "tested"),
                "unfinished": sum(1 for item in coverage.operations if item.outcome in {"not_tested", "retest"}),
            },
            "backend_runs": [run.model_dump(mode="json") for run in runs],
            "corpus": {
                "cases": len(corpus),
                "generated": sum(1 for case in corpus if case.status == "generated"),
                "failed": sum(1 for case in corpus if case.status == "failed"),
            },
            "campaigns": len(self.store.list_campaigns()),
            "integrity": self.check(manifest.campaign_id),
        }

    def check(self, campaign_id: str) -> dict[str, Any]:
        """Recompute source/reference/event identities without mutating state."""

        manifest = self._load(campaign_id)
        checks: dict[str, bool] = {}
        details: list[str] = []
        current_source, _, missing = scoped_source_digest(self.root_path, manifest.source_paths)
        checks["source_digest"] = current_source == manifest.source_digest
        if not checks["source_digest"]:
            details.append("scoped source digest drift")
        if missing:
            details.append(f"missing source paths: {', '.join(missing)}")

        reference_lock = self.store.read_json(campaign_id, "reference-lock.json")
        checks["reference_lock_digest"] = json_digest(reference_lock) == manifest.reference_lock_digest
        if not checks["reference_lock_digest"]:
            details.append("reference-lock digest drift")
        reference_files_ok = True
        campaign_dir = self.store.campaign_dir(campaign_id)
        for entry in reference_lock.get("files", []):
            path = (campaign_dir / str(entry.get("path", ""))).resolve()
            if campaign_dir.resolve() not in path.parents or not path.is_file():
                reference_files_ok = False
                details.append(f"missing reference artifact: {entry.get('path')}")
                continue
            if sha256_bytes(path.read_bytes()) != entry.get("sha256"):
                reference_files_ok = False
                details.append(f"reference artifact drift: {entry.get('path')}")
        checks["reference_files"] = reference_files_ok
        checks["scope_digest"] = sha256_bytes((campaign_dir / "scope.md").read_bytes()) == manifest.scope_digest
        if not checks["scope_digest"]:
            details.append("scope.md digest drift")
        coverage = self.store.load_coverage(campaign_id)
        checks["coverage_source_digest"] = coverage.source_digest == manifest.source_digest
        if not checks["coverage_source_digest"]:
            details.append("coverage source digest drift")
        checks["coverage_reference_lock_digest"] = (
            coverage.reference_lock_digest == manifest.reference_lock_digest
        )
        if not checks["coverage_reference_lock_digest"]:
            details.append("coverage reference-lock digest drift")
        queue = self.store.load_queue(campaign_id)
        checks["queue_reference_lock_digest"] = (
            queue.reference_lock_digest == manifest.reference_lock_digest
        )
        if not checks["queue_reference_lock_digest"]:
            details.append("queue reference-lock digest drift")
        events = self.store.read_events(campaign_id)
        checks["event_sequence"] = [event.sequence for event in events] == list(range(1, len(events) + 1))
        if not checks["event_sequence"]:
            details.append("event sequence is not contiguous")
        return {"passed": all(checks.values()), "checks": checks, "details": details}

    # ------------------------------------------------------------------
    # Internal transition helpers
    # ------------------------------------------------------------------

    def _load(self, campaign_id: str) -> HarnessManifest:
        try:
            return self.store.load_manifest(campaign_id)
        except HarnessStateError as exc:
            raise HarnessError(str(exc)) from exc

    def _begin(self, manifest: HarnessManifest, phase: str, command: str) -> None:
        if manifest.status == "complete":
            raise HarnessError("campaign is complete; start a new campaign for new evidence")
        if phase != manifest.phase and phase not in _PHASE_TRANSITIONS.get(manifest.phase, set()):
            raise HarnessError(f"illegal harness transition {manifest.phase!r} -> {phase!r}")
        previous = manifest.phase
        manifest.phase = phase  # type: ignore[assignment]
        manifest.checkpoint = HarnessCheckpoint(
            status="advanced",
            last_completed=previous,
            last_command=command,
            last_observation="Material action started; resume from this checkpoint if interrupted.",
            result_class="advanced",
            next_action=f"Complete phase {phase} and persist its observation.",
        )
        self.store.save_manifest(manifest)
        self.store.append_event(manifest.campaign_id, f"{phase}.started", manifest.phase, {"command": command})

    def _complete(
        self,
        manifest: HarnessManifest,
        *,
        next_phase: str,
        observation: str,
        next_action: str,
        event_type: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        if next_phase not in _PHASE_TRANSITIONS.get(manifest.phase, set()):
            raise HarnessError(f"illegal harness transition {manifest.phase!r} -> {next_phase!r}")
        previous = manifest.phase
        manifest.phase = next_phase  # type: ignore[assignment]
        manifest.status = "complete" if next_phase == "complete" else "active"
        manifest.checkpoint = HarnessCheckpoint(
            status="complete",
            last_completed=previous,
            last_command=manifest.checkpoint.last_command,
            last_observation=observation,
            result_class="advanced",
            files_written=[],
            next_action=next_action,
        )
        self.store.save_manifest(manifest)
        self.store.append_event(manifest.campaign_id, event_type, manifest.phase, payload or {})

    def _pause(
        self,
        manifest: HarnessManifest,
        *,
        observation: str,
        next_action: str,
        event_type: str,
        result_class: str = "operational-failure",
    ) -> None:
        manifest.status = "paused"
        manifest.phase = "paused"
        manifest.checkpoint = HarnessCheckpoint(
            status="paused",
            last_completed=manifest.checkpoint.last_completed,
            last_command=manifest.checkpoint.last_command,
            last_observation=observation,
            result_class=result_class,
            next_action=next_action,
        )
        self.store.save_manifest(manifest)
        self.store.append_event(manifest.campaign_id, event_type, "paused", {"observation": observation})

    def _prepare_candidate_poc(
        self,
        manifest: HarnessManifest,
        candidate: Any,
        *,
        write_test_dir: bool,
        requested_test_path: Path | None,
    ) -> tuple[Path | None, Any]:
        config = self.storage.load_project_config()
        if config.adapter != "evm":
            raise HarnessError(f"no stable proof adapter for {config.adapter}")
        adapter = EVMAdapter(self.root_path)
        index = self.storage.load_record("ingest", "evm_index")
        if index:
            adapter._index = index  # type: ignore[attr-defined]
        else:
            adapter.ingest_project(config)
        state_plan = get_or_build_candidate_state_plan(self.storage, candidate.id)
        proof = adapter.detect_proof_targets(candidate)
        generator = proof[0] if proof else None
        targets = proof[1] if proof else None
        poc = adapter.generate_poc(candidate, state_plan=state_plan, poc_location="evidence")
        if not poc:
            raise HarnessError("adapter could not generate a proof artifact")
        artifact = self.store.write_text(
            manifest.campaign_id,
            Path("evidence") / f"{candidate.id.replace('-', '_')}.t.sol",
            poc,
            overwrite=True,
        )
        candidate.evidence.poc_path = str(artifact)
        candidate.evidence.notes.append(
            f"Harness proof artifact generated in campaign {manifest.campaign_id}."
        )
        runnable_path = requested_test_path
        if write_test_dir:
            if generator is not None and targets is not None:
                runnable_source = generator.render_poc(candidate, targets, poc_location="test/zeropath")
                runnable_path = write_runnable_poc(self.root_path, candidate, runnable_source)
            else:
                runnable_path = write_candidate_test(
                    self.root_path,
                    candidate,
                    state_plan=state_plan,
                    force=False,
                )
            candidate.evidence.notes.append(f"Runnable test written to {runnable_path}")
        self.storage.save_candidate(candidate)
        return runnable_path, generator

    def _apply_backend_evidence(self, candidate: Any, run: BackendRun, generator: Any) -> None:
        candidate.evidence.trace_path = run.evidence_path
        if run.backend == "foundry":
            candidate.evidence.forge_result = run.status
        if run.status == "passed":
            candidate.status = "poc_passed"
        else:
            candidate.status = "needs_evidence"
        if generator is not None and run.backend == "foundry":
            from zeropath.adapters.evm.inflation_poc import parse_measured_events

            measured = parse_measured_events(run.stdout)
            generator.interpret(candidate, run.model_dump(mode="json"), measured)

    def _update_coverage_for_candidate(self, campaign_id: str, candidate: Any, run: BackendRun) -> None:
        coverage = self.store.load_coverage(campaign_id)
        names = set(candidate.entrypoints)
        for operation in coverage.operations:
            function_name = operation.entry_point.rsplit(".", 1)[-1]
            if operation.entry_point in names or function_name in names:
                operation.outcome = "tested"
                operation.evidence.append(run.evidence_path or run.run_id)
                operation.observed_result = f"{run.backend}: {run.status}"
                operation.next_action = "Review the trace and judge result; tested is not a safety claim."
        self.store.save_coverage(coverage, campaign_id)

    def _new_campaign_id(self) -> str:
        stamp = utc_now().strftime("%Y%m%d-%H%M%S")
        return f"H-{stamp}-{uuid.uuid4().hex[:8]}"


def _limits_for_budget(budget: str) -> dict[str, int]:
    return {
        "small": {"max_cards": 4, "max_deep_cycles": 1},
        "standard": {"max_cards": 8, "max_deep_cycles": 2},
        "extended": {"max_cards": 16, "max_deep_cycles": 4},
    }[budget]


def _corpus_limits(budget: str) -> tuple[int, int]:
    return {
        "small": (4, 4),
        "standard": (8, 8),
        "extended": (16, 12),
    }[budget]


def _production_paths(paths: Iterable[str]) -> list[str]:
    """Exclude conventional generated/test trees from an inferred scope.

    An explicit ``--scope-path`` is always honored.  Inferred scopes come from
    the parser's file list, which can include Foundry tests; generated PoCs must
    not invalidate the production source lock merely by being written.
    """

    excluded_roots = {".zeropath", "test", "tests", "script", "scripts", "cache", "out"}
    filtered = [
        str(path)
        for path in paths
        if str(path).replace("\\", "/").split("/", 1)[0].lower() not in excluded_roots
    ]
    return filtered or [str(path) for path in paths]


def _build_operations(index: dict[str, Any], intent: Any) -> list[HarnessOperation]:
    invariant_ids = [item.id for item in (intent.critical_invariants if intent else [])]
    operations: list[HarnessOperation] = []
    for function in index.get("functions", []):
        visibility = function.get("visibility")
        if visibility not in {"public", "external"}:
            continue
        file = function.get("file", "")
        contract = function.get("contract", "")
        name = function.get("name", "")
        if not name:
            continue
        key = f"{file}:{contract}:{name}:{function.get('line_start', 0)}"
        op_id = f"OP-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}"
        modifiers = function.get("modifiers") or []
        caller_class = "role-gated/unknown" if modifiers else "permissionless/unknown"
        touched = [
            str(flow.get("keyword") or flow.get("asset") or flow.get("description"))
            for flow in index.get("asset_flows", [])
            if flow.get("function") == name and flow.get("contract") == contract
        ]
        operations.append(
            HarnessOperation(
                id=op_id,
                area=str(index.get("protocol_type") or "unknown"),
                entry_point=f"{contract}.{name}",
                caller_class=caller_class,
                state_touched=sorted(set(item for item in touched if item)),
                invariants=invariant_ids,
                preconditions=["Source parser is heuristic; confirm modifier and deployment reachability."],
                next_action="Map the normal flow and attach executable evidence.",
            )
        )
    return operations


def _queue_item_for_candidate(
    candidate: Any,
    *,
    discovery_stream: str = "source-native",
) -> HarnessQueueItem:
    has_shape = bool(
        candidate.impact.funds_at_risk
        and candidate.attacker_model
        and candidate.entrypoints
        and candidate.required_state
        and candidate.transaction_sequence
        and candidate.root_cause_locations
    )
    bucket = "B" if has_shape else "C"
    gate = {
        "victim_and_loss": "candidate describes funds-at-risk" if candidate.impact.funds_at_risk else "missing concrete victim/loss",
        "ordinary_attacker": "untrusted attacker model present" if candidate.attacker_model else "missing attacker model",
        "attacker_cost": "unresolved; requires arithmetic",
        "official_path": "entrypoints and sequence are heuristic; requires source proof",
        "paid_floor": "unresolved; quick mode has no program payout rules",
        "next_missing_proof": "scope, economics, official-path, and paid-floor confirmation",
    }
    status = "candidate" if bucket == "B" else "disproven"
    notes = (
        "B: source-native mechanism is concrete enough for bounded proof, but quick mode does not "
        "supply program scope or economic confirmation."
        if bucket == "B"
        else "C: missing a concrete victim, attacker path, or state sequence; do not spend deep proof budget."
    )
    return HarnessQueueItem(
        id=candidate.id,
        area=candidate.protocol_type or "unknown",
        priority=0 if bucket == "B" else 100,
        impact_classes=[candidate.impact.impact_type],
        target_invariant=candidate.affected_invariant or "",
        entry_points=list(candidate.entrypoints),
        attacker_model=candidate.attacker_model or "",
        preconditions=list(candidate.required_state),
        hypothesis=candidate.title,
        discovery_stream=discovery_stream,
        mechanism_tags=list(candidate.tags),
        precision_bucket=bucket,  # type: ignore[arg-type]
        precision_gate=gate,
        transaction_sequence=list(candidate.transaction_sequence),
        status=status,  # type: ignore[arg-type]
        notes=notes,
    )


def _toolchain_snapshot(root: Path, backends: list[str]) -> dict[str, Any]:
    versions: dict[str, str] = {"python": sys.version.split()[0]}
    for backend in backends:
        binary = {"foundry": "forge", "echidna": "echidna", "medusa": "medusa", "halmos": "halmos"}.get(backend)
        if not binary or shutil.which(binary) is None:
            versions[backend] = "unavailable"
            continue
        try:
            result = subprocess.run(
                [binary, "--version"],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
                shell=False,
            )
            versions[backend] = (result.stdout or result.stderr).strip()[:300] or "available"
        except (OSError, subprocess.TimeoutExpired):
            versions[backend] = "unknown"
    versions["availability"] = backend_availability()
    return versions


def _git_status(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "status", "--short", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    return result.stdout.strip()[:4000] or "clean"


def _scope_document(config: Any, campaign_id: str, source_paths: list[str], missing: list[str], commit: str | None) -> str:
    missing_line = ", ".join(missing) if missing else "none"
    commit_line = commit or "source-tree digest (not a git repository)"
    return "\n".join(
        [
            "# ZeroPath harness scope (best effort)",
            "",
            f"- Campaign: `{campaign_id}`",
            f"- Project: `{config.project_id}`",
            f"- Target root: `{config.root_path}`",
            f"- Audited source identity: `{commit_line}`",
            "- Access mode: `local-only`",
            "- Public-chain writes: prohibited",
            "- Real funds/users: excluded",
            "- Program severity/duplicate rules: not supplied; human confirmation required",
            "- Liveness/consensus: out of scope unless explicitly added to a future frame",
            "",
            "## Frozen source paths",
            "",
            *[f"- `{path}`" for path in source_paths],
            f"- Missing requested paths: `{missing_line}`",
            "",
            "Generated artifacts are routing state. A candidate is never a finding without a human-defensible executable proof and judge review.",
            "",
        ]
    )


def _frame_facts_document(config: Any, index: dict[str, Any], backends: list[str], source_digest: str) -> str:
    return "\n".join(
        [
            "# Harness frame facts",
            "",
            f"- Adapter: `{config.adapter}`",
            f"- Build system: `{config.build_system or 'unknown'}`",
            f"- Protocol type: `{index.get('protocol_type', 'unknown')}`",
            f"- Indexed contracts: `{len(index.get('contracts', []))}`",
            f"- Indexed public/external functions: `{sum(1 for fn in index.get('functions', []) if fn.get('visibility') in {'public', 'external'})}`",
            f"- Backends requested: `{', '.join(backends)}`",
            f"- Scoped source digest: `{source_digest}`",
            "- Parser confidence: heuristic; inheritance, modifiers, and runtime reachability require proof.",
            "- Active actors: abstract attacker/victim labels only; no credentials or deployed identities.",
            "",
        ]
    )


def _handoff_document(manifest: HarnessManifest, candidate: Any, result: Any) -> str:
    blocking = "; ".join(result.blocking_objections) or "none"
    next_steps = "; ".join(result.required_next_steps) or "human review"
    return "\n".join(
        [
            "# Harness handoff",
            "",
            f"- Campaign: `{manifest.campaign_id}`",
            f"- Candidate: `{candidate.id}` — {candidate.title}",
            f"- Verdict: `{'SUBMIT-READY-PENDING-HUMAN' if result.report_ready else 'NEEDS-REPRO'}`",
            f"- Severity: `{result.severity}`",
            f"- Blocking objections: {blocking}",
            f"- Required next steps: {next_steps}",
            "- No public-chain mutation was performed by the harness.",
            "- Coverage remains an accounting of tested operations, not a safety claim.",
            "",
        ]
    )


__all__ = ["HarnessController", "HarnessError"]
