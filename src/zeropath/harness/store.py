"""Filesystem event store for resumable ZeroPath harness campaigns."""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path
from typing import Any

from zeropath.core.storage import Storage
from zeropath.core.utils import utc_now
from zeropath.harness.models import (
    BackendRun,
    CorpusCase,
    HarnessCoverage,
    HarnessEvent,
    HarnessManifest,
    HarnessMetrics,
    HarnessQueue,
)


class HarnessStateError(RuntimeError):
    """Raised when a campaign is missing or its durable state is invalid."""


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")


class HarnessStore:
    """Persist campaign state under ``.zeropath/harness``.

    The JSON snapshots are convenient materialized views.  ``events.jsonl`` is
    append-only and is the recovery/audit trail for every phase transition and
    backend observation.  Writes use a temporary sibling plus ``os.replace`` so
    an interrupted process cannot leave a half-written snapshot.
    """

    def __init__(self, root_path: str | Path = ".") -> None:
        self.root_path = Path(root_path).resolve()
        self.storage = Storage(self.root_path)
        self.harness_root = self.storage.zp_dir / "harness"
        self.campaigns_root = self.harness_root / "campaigns"

    def ensure_root(self) -> None:
        self.campaigns_root.mkdir(parents=True, exist_ok=True)

    def campaign_dir(self, campaign_id: str) -> Path:
        if not _ID_RE.fullmatch(campaign_id):
            raise HarnessStateError(f"invalid campaign id: {campaign_id!r}")
        return self.campaigns_root / campaign_id

    def create_campaign(
        self,
        manifest: HarnessManifest,
        *,
        text_files: dict[str, str],
        json_files: dict[str, Any],
    ) -> Path:
        """Create a campaign once; refuse to overwrite an existing run."""

        self.ensure_root()
        directory = self.campaign_dir(manifest.campaign_id)
        if directory.exists():
            raise HarnessStateError(f"campaign already exists: {manifest.campaign_id}")
        directory.mkdir(parents=True)
        (directory / "evidence").mkdir()
        (directory / "corpus").mkdir()
        (directory / "runs").mkdir()
        self.save_manifest(manifest)
        for relative, content in text_files.items():
            self.write_text(manifest.campaign_id, relative, content, overwrite=False)
        for relative, payload in json_files.items():
            self.write_json(manifest.campaign_id, relative, payload, overwrite=False)
        self.append_event(
            manifest.campaign_id,
            "campaign.created",
            manifest.phase,
            {"source_digest": manifest.source_digest, "backends": manifest.backends},
        )
        return directory

    def list_campaigns(self) -> list[HarnessManifest]:
        self.ensure_root()
        manifests: list[HarnessManifest] = []
        for directory in sorted(self.campaigns_root.iterdir()):
            if not directory.is_dir() or not _ID_RE.fullmatch(directory.name):
                continue
            try:
                manifests.append(self.load_manifest(directory.name))
            except HarnessStateError:
                continue
        return sorted(manifests, key=lambda item: item.updated_at, reverse=True)

    def latest_campaign(self) -> HarnessManifest | None:
        campaigns = self.list_campaigns()
        return campaigns[0] if campaigns else None

    def load_manifest(self, campaign_id: str) -> HarnessManifest:
        return self._load_model(campaign_id, "run.json", HarnessManifest)

    def save_manifest(self, manifest: HarnessManifest) -> None:
        manifest.updated_at = utc_now()
        self.write_json(manifest.campaign_id, "run.json", manifest.model_dump(mode="json"))

    def load_coverage(self, campaign_id: str) -> HarnessCoverage:
        return self._load_model(campaign_id, "coverage.json", HarnessCoverage)

    def save_coverage(self, coverage: HarnessCoverage, campaign_id: str) -> None:
        coverage.last_updated = utc_now()
        self.write_json(campaign_id, "coverage.json", coverage.model_dump(mode="json"))

    def load_queue(self, campaign_id: str) -> HarnessQueue:
        return self._load_model(campaign_id, "attack-surface.json", HarnessQueue)

    def save_queue(self, queue: HarnessQueue, campaign_id: str) -> None:
        self.write_json(campaign_id, "attack-surface.json", queue.model_dump(mode="json"))

    def load_metrics(self, campaign_id: str) -> HarnessMetrics:
        return self._load_model(campaign_id, "metrics.json", HarnessMetrics)

    def save_metrics(self, metrics: HarnessMetrics, campaign_id: str) -> None:
        metrics.last_updated = utc_now()
        self.write_json(campaign_id, "metrics.json", metrics.model_dump(mode="json"))

    def save_backend_run(self, run: BackendRun) -> Path:
        return self.write_json(
            run.campaign_id,
            Path("runs") / f"{run.run_id}.json",
            run.model_dump(mode="json"),
            overwrite=True,
        )

    def load_backend_run(self, campaign_id: str, run_id: str) -> BackendRun:
        return self._load_model(campaign_id, Path("runs") / f"{run_id}.json", BackendRun)

    def list_backend_runs(self, campaign_id: str) -> list[BackendRun]:
        directory = self._resolve_file(campaign_id, "runs")
        if not directory.exists():
            return []
        runs: list[BackendRun] = []
        for path in sorted(directory.glob("*.json")):
            try:
                runs.append(BackendRun.model_validate(self._read_json(path)))
            except (OSError, ValueError):
                continue
        return sorted(runs, key=lambda item: item.started_at)

    def save_corpus_case(self, case: CorpusCase, campaign_id: str) -> Path:
        if not _ID_RE.fullmatch(case.case_id):
            raise HarnessStateError(f"invalid corpus case id: {case.case_id!r}")
        return self.write_json(
            campaign_id,
            Path("corpus") / "cases" / f"{case.case_id}.json",
            case,
            overwrite=True,
        )

    def load_corpus_case(self, campaign_id: str, case_id: str) -> CorpusCase:
        if not _ID_RE.fullmatch(case_id):
            raise HarnessStateError(f"invalid corpus case id: {case_id!r}")
        return self._load_model(
            campaign_id,
            Path("corpus") / "cases" / f"{case_id}.json",
            CorpusCase,
        )

    def list_corpus_cases(self, campaign_id: str) -> list[CorpusCase]:
        directory = self._resolve_file(campaign_id, Path("corpus") / "cases")
        if not directory.exists():
            return []
        cases: list[CorpusCase] = []
        for path in sorted(directory.glob("*.json")):
            try:
                cases.append(CorpusCase.model_validate(self._read_json(path)))
            except (OSError, ValueError):
                continue
        return sorted(cases, key=lambda item: item.created_at)

    def append_event(
        self,
        campaign_id: str,
        event_type: str,
        phase: str,
        payload: dict[str, Any] | None = None,
    ) -> HarnessEvent:
        """Append one event and fsync it before returning."""

        directory = self.campaign_dir(campaign_id)
        if not directory.exists():
            raise HarnessStateError(f"campaign not found: {campaign_id}")
        events_path = directory / "events.jsonl"
        sequence = 1
        if events_path.exists():
            with events_path.open("rb") as handle:
                for line in handle:
                    if line.strip():
                        sequence += 1
        event = HarnessEvent(
            sequence=sequence,
            event_id=uuid.uuid4().hex,
            campaign_id=campaign_id,
            event_type=event_type,
            phase=phase,  # type: ignore[arg-type]
            payload=payload or {},
        )
        with events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.model_dump(mode="json"), sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return event

    def read_events(self, campaign_id: str) -> list[HarnessEvent]:
        path = self._resolve_file(campaign_id, "events.jsonl")
        if not path.exists():
            return []
        events: list[HarnessEvent] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(HarnessEvent.model_validate(json.loads(line)))
        return events

    def write_text(
        self,
        campaign_id: str,
        relative_path: str | Path,
        content: str,
        *,
        overwrite: bool = True,
    ) -> Path:
        path = self._resolve_file(campaign_id, relative_path)
        if path.exists() and not overwrite:
            raise HarnessStateError(f"refusing to overwrite harness artifact: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        self._atomic_write(path, content.encode("utf-8"))
        return path

    def write_json(
        self,
        campaign_id: str,
        relative_path: str | Path,
        payload: Any,
        *,
        overwrite: bool = True,
    ) -> Path:
        if hasattr(payload, "model_dump"):
            payload = payload.model_dump(mode="json")
        content = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        return self.write_text(campaign_id, relative_path, content, overwrite=overwrite)

    def read_json(self, campaign_id: str, relative_path: str | Path) -> Any:
        return self._read_json(self._resolve_file(campaign_id, relative_path))

    def _load_model(self, campaign_id: str, relative_path: str | Path, model_type: Any) -> Any:
        path = self._resolve_file(campaign_id, relative_path)
        if not path.exists():
            raise HarnessStateError(f"missing harness artifact: {path}")
        try:
            return model_type.model_validate(self._read_json(path))
        except (OSError, ValueError) as exc:
            raise HarnessStateError(f"invalid harness artifact: {path}: {exc}") from exc

    def _resolve_file(self, campaign_id: str, relative_path: str | Path) -> Path:
        directory = self.campaign_dir(campaign_id)
        path = (directory / relative_path).resolve()
        if path != directory.resolve() and directory.resolve() not in path.parents:
            raise HarnessStateError(f"artifact path escapes campaign: {relative_path}")
        return path

    @staticmethod
    def _read_json(path: Path) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise HarnessStateError(f"cannot read harness artifact: {path}") from exc

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()


__all__ = ["HarnessStateError", "HarnessStore"]
