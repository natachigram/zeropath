"""
Halmos symbolic-execution wrapper — Phase 5.

Spec (phases.md, PHASE 5, "Symbolic execution"):
    "Integrate Halmos for invariant verification. For each Phase 2 invariant
     that has a formal_spec, run Halmos to check whether it is formally
     provable or falsifiable. This is more rigorous than simulation for
     coverage of all possible inputs."

Halmos is a Python package that compiles Solidity tests and runs symbolic
execution. We invoke it as a CLI subprocess so this module doesn't take a
hard import dependency on it (the package may not be installed and is
non-trivial to ship transitively).

Each :class:`Invariant` whose ``formal_spec.halmos`` field is populated is
turned into one Solidity test function:

    function check_<inv_id>(uint256 x) public {{
        // symbolic input x is left to Halmos
        require({halmos_spec});
    }}

Halmos prints ``[PASS]`` for symbolic-proved tests, ``[FAIL]`` with a
counter-example otherwise. We parse those into :class:`HalmosCheck` rows.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Iterable, Optional

from zeropath.invariants.models import Invariant
from zeropath.simulator.models import HalmosCheck, HalmosResult

logger = logging.getLogger(__name__)


_HALMOS_TEST_TEMPLATE = """\
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// Synthesised by ZeroPath Phase 5 — Halmos symbolic-execution tests.
// Each `check_*` corresponds to one Phase 2 invariant's formal_spec.halmos.

contract ZeroPathHalmosTests {{
{tests}
}}
"""


_HALMOS_PASS_RE = re.compile(r"\[PASS\]\s+(check_\S+)")
_HALMOS_FAIL_RE = re.compile(r"\[FAIL\]\s+(check_\S+)")
_HALMOS_COUNTER_RE = re.compile(r"Counterexample:\s*(.*?)(?:\n\n|\Z)", re.DOTALL)


def _safe_test_name(inv: Invariant, idx: int) -> str:
    base = re.sub(r"[^a-zA-Z0-9]+", "_", inv.type.value or "invariant").strip("_")
    return f"check_{base}_{idx}"[:60]


def _synthesise_tests(invariants: list[Invariant]) -> str:
    parts: list[str] = []
    for i, inv in enumerate(invariants):
        if not (inv.formal_spec and inv.formal_spec.halmos):
            continue
        name = _safe_test_name(inv, i)
        # The halmos spec field is a free-form expression. We wrap it in
        # `require(...)` so Halmos can prove the predicate must hold for any
        # symbolic input. If Halmos finds inputs that make `require` fail it
        # reports `[FAIL]` and a counterexample.
        spec = inv.formal_spec.halmos.strip().rstrip(";")
        parts.append(
            f"    function {name}(uint256 x) public pure {{\n"
            f"        // {inv.description}\n"
            f"        require({spec});\n"
            f"    }}\n"
        )
    if not parts:
        return ""
    return _HALMOS_TEST_TEMPLATE.format(tests="\n".join(parts))


class HalmosChecker:
    """
    Run Halmos against Phase 2 invariants and return per-invariant results.

    Parameters
    ----------
    binary : str
        Path/name of the Halmos CLI (defaults to ``halmos``).
    timeout_seconds : int
        Hard cap per invocation.
    extra_args : list[str] | None
        Forwarded verbatim, e.g. ``["--loop", "8", "--solver-timeout-assertion", "30000"]``.
    """

    def __init__(
        self,
        *,
        binary: str = "halmos",
        timeout_seconds: int = 120,
        extra_args: Optional[list[str]] = None,
    ) -> None:
        self.binary = binary
        self.timeout_seconds = timeout_seconds
        self.extra_args = list(extra_args or [])

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def check(self, invariants: Iterable[Invariant]) -> list[HalmosCheck]:
        """
        Returns one :class:`HalmosCheck` per *eligible* invariant — i.e.
        invariants that have a ``formal_spec.halmos`` string. Invariants
        without one are skipped (no row emitted).
        """
        eligible: list[Invariant] = [
            inv for inv in invariants
            if inv.formal_spec and inv.formal_spec.halmos
        ]
        if not eligible:
            return []
        if not self.is_available():
            logger.info("halmos binary not found — emitting SKIPPED for %d invariants", len(eligible))
            return [
                HalmosCheck(
                    invariant_id=inv.id,
                    formal_spec=inv.formal_spec.halmos,
                    result=HalmosResult.SKIPPED,
                    notes="halmos not installed",
                )
                for inv in eligible
            ]

        source = _synthesise_tests(eligible)
        if not source:
            return []

        workdir = Path(tempfile.mkdtemp(prefix="zp_halmos_"))
        try:
            tests_path = workdir / "ZeroPathHalmosTests.sol"
            tests_path.write_text(source, encoding="utf-8")
            start = time.monotonic()
            proc = subprocess.run(
                [self.binary, "--contract", "ZeroPathHalmosTests", *self.extra_args],
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            elapsed = round(time.monotonic() - start, 3)
            return self._parse(proc.stdout or "", eligible, elapsed)
        except subprocess.TimeoutExpired:
            return [
                HalmosCheck(
                    invariant_id=inv.id,
                    formal_spec=inv.formal_spec.halmos,
                    result=HalmosResult.UNKNOWN,
                    elapsed_seconds=self.timeout_seconds,
                    notes=f"halmos timed out after {self.timeout_seconds}s",
                )
                for inv in eligible
            ]
        finally:
            try:
                import shutil as _sh
                _sh.rmtree(workdir, ignore_errors=True)
            except Exception:
                pass

    def _parse(
        self,
        stdout: str,
        invariants: list[Invariant],
        elapsed: float,
    ) -> list[HalmosCheck]:
        results: list[HalmosCheck] = []
        passes = {m.group(1) for m in _HALMOS_PASS_RE.finditer(stdout)}
        fails = {m.group(1) for m in _HALMOS_FAIL_RE.finditer(stdout)}
        counter = _HALMOS_COUNTER_RE.search(stdout)
        counter_text = counter.group(1).strip() if counter else None

        for i, inv in enumerate(invariants):
            name = _safe_test_name(inv, i)
            if name in fails:
                result = HalmosResult.FALSIFIED
            elif name in passes:
                result = HalmosResult.PROVED
            else:
                result = HalmosResult.UNKNOWN
            results.append(HalmosCheck(
                invariant_id=inv.id,
                formal_spec=inv.formal_spec.halmos,
                result=result,
                counter_example=counter_text if result == HalmosResult.FALSIFIED else None,
                elapsed_seconds=elapsed,
                notes="" if result != HalmosResult.UNKNOWN else "halmos reported no verdict",
            ))
        return results

    # ------------------------------------------------------------------
    # Aggregate helper
    # ------------------------------------------------------------------

    @staticmethod
    def summarise(checks: Iterable[HalmosCheck]) -> HalmosResult:
        """
        Roll up a set of per-invariant checks into a single status:

          * FALSIFIED — any falsified invariant dominates
          * PROVED    — all proved
          * UNKNOWN   — at least one unknown but none falsified
          * SKIPPED   — only skipped checks
        """
        checks_list = list(checks)
        if not checks_list:
            return HalmosResult.SKIPPED
        if any(c.result == HalmosResult.FALSIFIED for c in checks_list):
            return HalmosResult.FALSIFIED
        if all(c.result == HalmosResult.SKIPPED for c in checks_list):
            return HalmosResult.SKIPPED
        if any(c.result == HalmosResult.UNKNOWN for c in checks_list):
            return HalmosResult.UNKNOWN
        return HalmosResult.PROVED
