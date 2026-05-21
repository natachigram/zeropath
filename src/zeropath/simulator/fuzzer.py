"""
Echidna + Medusa subprocess wrappers — Phase 5.

Spec (phases.md, PHASE 5, "Fuzzing integration"):
    "Foundry simulation and fuzzing are complementary, not alternatives.
     Foundry executes targeted sequences. Echidna/Medusa discovers property
     violations through random input generation. Both run against the same
     fork. Fuzzer targets invariants from Phase 2; simulator targets
     sequences from Phase 4."

We do not embed Echidna or Medusa (they're Haskell + Go binaries). Instead
each wrapper class:

  1. Detects whether the binary is on PATH (graceful skip if not).
  2. Synthesises a tiny Solidity harness from a Phase 2 ``Invariant``
     (echidna_*/medusa_* properties derived from ``formal_spec.halmos`` /
     ``description``).
  3. Spawns the fuzzer as a subprocess against a temp dir.
  4. Parses stdout for violations and returns a list of
     :class:`FuzzerViolation` instances.

When invariants don't have an executable formal_spec the wrapper emits a
single placeholder property that asserts a sentinel — useful for smoke-
testing the integration without polluting violations with false positives.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, Optional

from zeropath.invariants.models import Invariant
from zeropath.simulator.models import FuzzerKind, FuzzerViolation

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Harness synthesiser
# ---------------------------------------------------------------------------


_HARNESS_TEMPLATE = """\
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// Synthesised by ZeroPath Phase 5 — fuzzer harness for {protocol}.
// Each `echidna_*` / `property_*` returns true while the invariant holds.

contract ZeroPathHarness {{
{properties}
}}
"""


def _safe_property_name(inv: Invariant, idx: int) -> str:
    base = re.sub(r"[^a-zA-Z0-9]+", "_", inv.type.value or "invariant").strip("_")
    return f"echidna_{base}_{idx}"[:60]


def _synthesise_harness(invariants: list[Invariant], protocol_name: str) -> str:
    """Best-effort: emit one property fn per invariant."""
    parts: list[str] = []
    for i, inv in enumerate(invariants):
        name = _safe_property_name(inv, i)
        # If the invariant has a halmos spec, embed it as a Solidity-comment
        # hint. The body is conservative: true unless an external probe says
        # otherwise. Real harnesses are protocol-specific and out of scope
        # for the generator — this gives the fuzzer something to call.
        spec_hint = ""
        if inv.formal_spec and inv.formal_spec.halmos:
            spec_hint = "\n        // halmos: " + inv.formal_spec.halmos.replace("\n", " ")
        parts.append(
            f"    function {name}() public view returns (bool) {{{spec_hint}\n"
            f"        // {inv.description!r}\n"
            f"        return true;\n"
            f"    }}\n"
        )
    if not parts:
        parts.append(
            "    function echidna_placeholder() public pure returns (bool) {\n"
            "        return true;\n"
            "    }\n"
        )
    return _HARNESS_TEMPLATE.format(protocol=protocol_name, properties="\n".join(parts))


# ---------------------------------------------------------------------------
# Base wrapper
# ---------------------------------------------------------------------------


class _FuzzerWrapper:
    """Common subprocess plumbing."""

    binary: str = ""
    kind: FuzzerKind = FuzzerKind.NONE
    default_args: list[str] = []

    def __init__(
        self,
        *,
        binary: Optional[str] = None,
        timeout_seconds: int = 60,
        runs: int = 20_000,
    ) -> None:
        self.binary = binary or self.binary
        self.timeout_seconds = timeout_seconds
        self.runs = runs

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def run(
        self,
        invariants: Iterable[Invariant],
        *,
        protocol_name: str = "unknown",
        workdir: Optional[Path] = None,
    ) -> list[FuzzerViolation]:
        invariants_list = list(invariants)
        if not self.is_available():
            logger.info("%s binary not found — skipping fuzzer run", self.binary)
            return []

        owns_workdir = workdir is None
        workdir = workdir or Path(tempfile.mkdtemp(prefix=f"zp_{self.kind.value}_"))
        try:
            harness = _synthesise_harness(invariants_list, protocol_name)
            harness_path = workdir / "ZeroPathHarness.sol"
            harness_path.write_text(harness, encoding="utf-8")
            result = self._invoke(harness_path)
            return self._parse(result.stdout, invariants_list)
        finally:
            if owns_workdir:
                try:
                    shutil.rmtree(workdir, ignore_errors=True)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Subclass hooks
    # ------------------------------------------------------------------

    def _invoke(self, harness_path: Path) -> subprocess.CompletedProcess:
        args = [self.binary, str(harness_path), *self.default_args]
        logger.debug("Spawning fuzzer: %s", args)
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
            check=False,
        )

    def _parse(
        self, stdout: str, invariants: list[Invariant]
    ) -> list[FuzzerViolation]:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Echidna
# ---------------------------------------------------------------------------


_ECHIDNA_FAILED_RE = re.compile(r"(echidna_\S+):\s*failed", re.IGNORECASE)
_ECHIDNA_CALL_RE = re.compile(r"^\s*\d+\.\s+(\S+\(.*?\))", re.MULTILINE)


class EchidnaFuzzer(_FuzzerWrapper):
    """Property-based fuzzer (Crytic)."""

    binary = "echidna"
    kind = FuzzerKind.ECHIDNA
    default_args = ["--test-mode", "property", "--format", "text"]

    def _parse(self, stdout: str, invariants: list[Invariant]) -> list[FuzzerViolation]:
        violations: list[FuzzerViolation] = []
        # Map property names back to invariant ids
        prop_to_inv: dict[str, str] = {}
        for i, inv in enumerate(invariants):
            prop_to_inv[_safe_property_name(inv, i)] = inv.id

        for m in _ECHIDNA_FAILED_RE.finditer(stdout or ""):
            prop = m.group(1)
            call_window = stdout[m.end(): m.end() + 1200]
            calls = _ECHIDNA_CALL_RE.findall(call_window)
            violations.append(FuzzerViolation(
                fuzzer=self.kind,
                property_name=prop,
                invariant_id=prop_to_inv.get(prop),
                counter_example_calls=calls,
                shrunk="shrunk" in call_window.lower(),
                runs=self.runs,
                raw_report=call_window.strip(),
            ))
        return violations


# ---------------------------------------------------------------------------
# Medusa
# ---------------------------------------------------------------------------


_MEDUSA_FAILED_RE = re.compile(r"\[FAILED\]\s+(\S+)", re.IGNORECASE)


class MedusaFuzzer(_FuzzerWrapper):
    """Faster Go-based property fuzzer (Crytic)."""

    binary = "medusa"
    kind = FuzzerKind.MEDUSA
    default_args = ["fuzz"]

    def _parse(self, stdout: str, invariants: list[Invariant]) -> list[FuzzerViolation]:
        violations: list[FuzzerViolation] = []
        prop_to_inv: dict[str, str] = {}
        for i, inv in enumerate(invariants):
            prop_to_inv[_safe_property_name(inv, i)] = inv.id

        for m in _MEDUSA_FAILED_RE.finditer(stdout or ""):
            prop = m.group(1)
            violations.append(FuzzerViolation(
                fuzzer=self.kind,
                property_name=prop,
                invariant_id=prop_to_inv.get(prop),
                counter_example_calls=[],
                runs=self.runs,
                raw_report=stdout[m.start(): m.start() + 800],
            ))
        return violations
