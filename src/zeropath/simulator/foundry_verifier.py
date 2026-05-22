"""
Foundry PoC Verifier — Contest mode.

Every contest submission needs a working PoC. The Phase 9 codegen produces
.t.sol files but nothing actually runs them. This module:

  1. Writes the generated Foundry test to a temp project (or an existing
     contest repo).
  2. Runs ``forge build`` to confirm it compiles.
  3. Runs ``forge test --match-path …`` to confirm the assertions pass.
  4. On compile/run failure, captures the full output so the LLM Reasoner
     can be asked to repair the PoC and retry.

Designed to be safe to import even when Foundry isn't installed — calls
to ``run()`` raise :class:`FoundryNotAvailable` so callers can degrade
gracefully (contest mode still produces template PoCs, just not validated
ones).
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass
class VerifierResult:
    """Outcome of one PoC verification attempt."""

    ok: bool
    stage: str                       # "compile" | "test" | "skipped"
    test_function: str = ""
    elapsed_seconds: float = 0.0
    stdout: str = ""
    stderr: str = ""
    error_summary: str = ""

    @property
    def passed_compile(self) -> bool:
        return self.stage in ("test",) and self.ok or (self.stage == "compile" and self.ok)

    @property
    def passed_test(self) -> bool:
        return self.stage == "test" and self.ok


@dataclass
class VerifierConfig:
    """Tunables for one verifier instance."""

    forge_binary: str = "forge"
    timeout_seconds: int = 120
    max_retries: int = 1
    extra_args: list[str] = field(default_factory=list)
    fork_url_env: str = "ETH_RPC_URL"
    fork_block: Optional[int] = None


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class FoundryNotAvailable(RuntimeError):
    """`forge` binary missing from PATH."""


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


class FoundryPoCVerifier:
    """
    Compile + run a generated Foundry test file.

    Two run modes:

      * **Existing repo** — point the verifier at a target Foundry project
        (the contest's own repo). PoC files are dropped under ``test/``
        and ``forge`` is invoked from the project root.

      * **Scratch workspace** — for standalone PoCs, the verifier builds
        a minimal Foundry project in a temp dir with the bundled
        ``foundry.toml`` and ``remappings.txt``. Useful when the contest
        scope doesn't ship a working Foundry config.

    The verifier deliberately does NOT call out to an LLM — repair is the
    Reasoner's job. ``run()`` returns enough error context for the
    Reasoner to drive that loop externally.
    """

    def __init__(self, config: Optional[VerifierConfig] = None) -> None:
        self.config = config or VerifierConfig()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_available(self) -> bool:
        return shutil.which(self.config.forge_binary) is not None

    def run(
        self,
        *,
        test_code: str,
        test_filename: str,
        test_function: str = "",
        project_root: Optional[str | Path] = None,
        keep_workspace: bool = False,
    ) -> VerifierResult:
        """
        Compile + run a generated Foundry test.

        Parameters
        ----------
        test_code : str
            Solidity source of the .t.sol PoC.
        test_filename : str
            Filename used inside ``test/`` (e.g. ``OracleAttack.t.sol``).
        test_function : str
            Optional ``--match-test`` selector; empty runs every test.
        project_root : str | Path | None
            Existing Foundry project. None creates a scratch workspace.
        keep_workspace : bool
            Don't delete the scratch dir on exit — helpful for debugging.
        """
        if not self.is_available:
            raise FoundryNotAvailable(
                f"`{self.config.forge_binary}` not on PATH; install Foundry"
            )

        owns_workspace = False
        if project_root is None:
            workspace = Path(tempfile.mkdtemp(prefix="zp_foundry_"))
            owns_workspace = True
            self._materialise_scratch_project(workspace)
        else:
            workspace = Path(project_root)
            if not (workspace / "foundry.toml").exists():
                logger.warning(
                    "FoundryPoCVerifier: %s has no foundry.toml — proceeding anyway",
                    workspace,
                )

        try:
            test_path = workspace / "test" / test_filename
            test_path.parent.mkdir(parents=True, exist_ok=True)
            test_path.write_text(test_code, encoding="utf-8")

            # 1. Compile
            compile_res = self._forge(["build"], cwd=workspace)
            if compile_res.returncode != 0:
                return VerifierResult(
                    ok=False, stage="compile",
                    test_function=test_function,
                    elapsed_seconds=compile_res.elapsed,
                    stdout=compile_res.stdout, stderr=compile_res.stderr,
                    error_summary=self._summarise_compile_failure(
                        compile_res.stdout + compile_res.stderr,
                    ),
                )

            # 2. Run test
            test_args = ["test", "--match-path", f"test/{test_filename}", "-vvv"]
            if test_function:
                test_args += ["--match-test", test_function]
            test_args += self.config.extra_args
            test_res = self._forge(test_args, cwd=workspace)
            ok = test_res.returncode == 0
            return VerifierResult(
                ok=ok, stage="test",
                test_function=test_function,
                elapsed_seconds=test_res.elapsed,
                stdout=test_res.stdout, stderr=test_res.stderr,
                error_summary=(
                    "" if ok else self._summarise_test_failure(
                        test_res.stdout + test_res.stderr,
                    )
                ),
            )
        finally:
            if owns_workspace and not keep_workspace:
                shutil.rmtree(workspace, ignore_errors=True)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _forge(self, args: list[str], *, cwd: Path) -> "_ProcResult":
        import time
        cmd = [self.config.forge_binary, *args]
        logger.debug("running: %s (cwd=%s)", " ".join(cmd), cwd)
        env = os.environ.copy()
        if self.config.fork_url_env and self.config.fork_url_env in env:
            env.setdefault("FOUNDRY_ETH_RPC_URL", env[self.config.fork_url_env])
        if self.config.fork_block:
            env["FOUNDRY_FORK_BLOCK_NUMBER"] = str(self.config.fork_block)
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd, cwd=str(cwd), env=env,
                capture_output=True, text=True,
                timeout=self.config.timeout_seconds,
                check=False,
            )
            elapsed = time.monotonic() - start
            return _ProcResult(
                returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr,
                elapsed=round(elapsed, 3),
            )
        except subprocess.TimeoutExpired as exc:
            return _ProcResult(
                returncode=124,
                stdout=(exc.stdout or b"").decode(errors="replace"),
                stderr=f"timed out after {self.config.timeout_seconds}s",
                elapsed=round(self.config.timeout_seconds, 3),
            )

    def _materialise_scratch_project(self, root: Path) -> None:
        """Drop minimal foundry.toml + remappings.txt in a fresh dir."""
        (root / "src").mkdir(parents=True, exist_ok=True)
        (root / "test").mkdir(parents=True, exist_ok=True)
        (root / "foundry.toml").write_text(
            "[profile.default]\n"
            "src = \"src\"\n"
            "test = \"test\"\n"
            "out = \"out\"\n"
            "libs = [\"lib\"]\n"
            "optimizer = true\n"
            "optimizer_runs = 200\n"
            "fs_permissions = [{ access = \"read-write\", path = \".\" }]\n",
            encoding="utf-8",
        )
        (root / "remappings.txt").write_text(
            "forge-std/=lib/forge-std/src/\n"
            "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/\n",
            encoding="utf-8",
        )

    @staticmethod
    def _summarise_compile_failure(combined: str) -> str:
        """Pull the first compile error line out of forge output."""
        for line in combined.splitlines():
            if "Error" in line and "(" in line:
                return line.strip()[:300]
        return "compile failed"

    @staticmethod
    def _summarise_test_failure(combined: str) -> str:
        for marker in ("[FAIL", "panicked", "revert", "assertion failed"):
            for line in combined.splitlines():
                if marker in line:
                    return line.strip()[:300]
        return "test failed"


# ---------------------------------------------------------------------------
# Result helper
# ---------------------------------------------------------------------------


@dataclass
class _ProcResult:
    returncode: int
    stdout: str
    stderr: str
    elapsed: float
