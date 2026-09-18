"""Stable, durable, evidence-first ZeroPath harness APIs."""

from zeropath.harness.backends import (
    BackendContext,
    BackendError,
    backend_availability,
    get_backend,
    run_named_backend,
    supported_backends,
)
from zeropath.harness.campaign import HarnessController, HarnessError
from zeropath.harness.corpus import case_fingerprint, generate_cases, shrink_case
from zeropath.harness.models import (
    BackendRun,
    CorpusAction,
    CorpusCase,
    HarnessCoverage,
    HarnessManifest,
    HarnessOperation,
    HarnessQueue,
)
from zeropath.harness.store import HarnessStateError, HarnessStore

__all__ = [
    "BackendContext",
    "BackendError",
    "BackendRun",
    "CorpusAction",
    "CorpusCase",
    "HarnessController",
    "HarnessCoverage",
    "HarnessError",
    "HarnessManifest",
    "HarnessOperation",
    "HarnessQueue",
    "HarnessStateError",
    "HarnessStore",
    "backend_availability",
    "case_fingerprint",
    "generate_cases",
    "get_backend",
    "run_named_backend",
    "shrink_case",
    "supported_backends",
]
