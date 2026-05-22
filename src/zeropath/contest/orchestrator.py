"""
ContestOrchestrator — top-level coordinator for the contest-winning pipeline.

Per-file flow::

    1. SpecMiner extracts claimed invariants from NatSpec + README + docs.
    2. LLMReasoner audits the file with Phase 8 KG RAG + spec claims as
       context. Returns LLMFindings.
    3. (Optional) FoundryPoCVerifier compiles + runs each generated PoC.
       Failing PoCs are sent back to the LLM for one retry.
    4. (Optional) LLMReasoner contrarian pass marks weak findings DISCARD.
    5. Findings are turned into SubmissionFinding rows.

Batch-level::

    6. SubmissionStrategy gates by confidence + severity floor and assigns
       duplicate-likelihood scores.
    7. Per-platform formatter renders the actionable subset.
    8. ContestReport captures cost + telemetry + ordered submissions.

Everything is best-effort: missing LLM provider, missing Foundry, missing
KG all degrade gracefully. The pipeline shape stays the same.
"""

from __future__ import annotations

import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, Optional

from zeropath.contest.models import (
    ContestConfig,
    ContestPlatform,
    ContestReport,
    Submission,
    SubmissionDisposition,
    SubmissionFinding,
)
from zeropath.contest.platforms import for_platform
from zeropath.contest.strategy import SubmissionStrategy
from zeropath.invariants.spec_miner import (
    SpecMiner,
    SpecMismatchDetector,
    render_claims_for_prompt,
)
from zeropath.knowledge.knowledge import KnowledgeGraphOrchestrator
from zeropath.llm.audit_corpus import AuditCorpus
from zeropath.llm.provider import (
    CostLedger,
    LLMProvider,
    LLMProviderUnavailable,
    build_default_provider,
)
from zeropath.llm.reasoner import LLMFinding, LLMReasoner

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class ContestOrchestrator:
    """
    Drive the contest pipeline against a target repo.

    Parameters
    ----------
    config : ContestConfig
        Run knobs (platform, scope, budget, thresholds).
    knowledge : KnowledgeGraphOrchestrator | None
        Phase 8 KG. Strongly recommended in contest mode for RAG +
        duplicate-likelihood scoring.
    llm_provider : LLMProvider | None
        Pre-built provider. None → ``build_default_provider()``.
    foundry_verifier : FoundryPoCVerifier | None
        Optional PoC validator. None disables compile/run verification.
    inferred_invariant_report : InvariantReport | None
        Optional Phase 2 output — boosts LLM context.
    """

    def __init__(
        self,
        config: ContestConfig,
        *,
        knowledge: Optional[KnowledgeGraphOrchestrator] = None,
        llm_provider: Optional[LLMProvider] = None,
        foundry_verifier=None,
        inferred_invariant_report=None,
    ) -> None:
        self.config = config
        self.knowledge = knowledge
        self.inferred_invariant_report = inferred_invariant_report

        self.repo_root = Path(config.repo_path).resolve()
        if not self.repo_root.exists():
            raise FileNotFoundError(f"contest repo_path does not exist: {self.repo_root}")

        # LLM stack
        self.llm_provider = llm_provider
        if self.llm_provider is None and config.use_llm:
            self.llm_provider = build_default_provider()
        self.cost_ledger = CostLedger(budget_usd=config.llm_budget_usd)
        self.corpus = AuditCorpus(knowledge) if knowledge is not None else None
        self.reasoner: Optional[LLMReasoner] = None
        if config.use_llm and self.llm_provider and self.llm_provider.is_available:
            self.reasoner = LLMReasoner(
                provider=self.llm_provider,
                corpus=self.corpus,
                repo_root=self.repo_root,
                cost_ledger=self.cost_ledger,
            )

        # Spec mining
        self.spec_miner = SpecMiner(
            self.repo_root,
            use_llm=config.use_spec_miner and config.use_llm,
            llm_provider=self.llm_provider,
        )
        self.mismatch_detector = SpecMismatchDetector()

        # PoC verifier
        self.foundry_verifier = foundry_verifier
        if config.use_foundry_verifier and self.foundry_verifier is None:
            try:
                from zeropath.simulator.foundry_verifier import (
                    FoundryPoCVerifier,
                )
                v = FoundryPoCVerifier()
                self.foundry_verifier = v if v.is_available else None
            except Exception:
                self.foundry_verifier = None

        # Submission strategy
        self.strategy = SubmissionStrategy(config, knowledge=knowledge)
        self.formatter = for_platform(config.platform)

        # Mutable state during a run
        self._files_scanned = 0
        self._raw_findings: list[LLMFinding] = []
        self._spec_claims: list = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> ContestReport:
        """Execute the full contest pipeline. Returns a ContestReport."""
        start = time.monotonic()
        scope_files = self._collect_scope()
        if not scope_files:
            logger.warning("ContestOrchestrator: no in-scope files found under %s", self.repo_root)

        # Stage 1: spec mine the whole repo (cheap, one pass).
        spec_result = None
        if self.config.use_spec_miner:
            try:
                spec_result = self.spec_miner.mine()
                self._spec_claims = list(spec_result.claimed_invariants)
                logger.info("SpecMiner extracted %d claimed invariants", len(self._spec_claims))
            except Exception:
                logger.exception("SpecMiner crashed; continuing without spec context")

        # Stage 2: parallel per-file audit.
        raw_findings = self._audit_files_parallel(scope_files)
        self._raw_findings = raw_findings

        # Stage 3: optional PoC verification + LLM contrarian.
        validated = self._verify_and_review(raw_findings)

        # Stage 4: spec-mismatch enrichment.
        if self.inferred_invariant_report and self._spec_claims:
            try:
                mismatches = self.mismatch_detector.detect(
                    claimed=self._spec_claims,
                    inferred_report=self.inferred_invariant_report,
                )
                validated.extend(self._mismatches_as_findings(mismatches))
            except Exception:
                logger.exception("spec-mismatch detector crashed")

        # Stage 5: strategy + ranking.
        prepared = self.strategy.assess(validated)

        # Stage 6: platform formatting.
        for sub in prepared:
            if sub.is_actionable:
                try:
                    sub.rendered_payload = self.formatter.render(sub)
                except Exception:
                    logger.exception("formatter failed for submission %s", sub.id)

        elapsed = round(time.monotonic() - start, 3)
        return self._build_report(prepared, scope_files, elapsed)

    # ------------------------------------------------------------------
    # Scope discovery
    # ------------------------------------------------------------------

    def _collect_scope(self) -> list[Path]:
        """Resolve in-scope files from config or by scanning the repo."""
        if self.config.scope_files:
            files = [self.repo_root / s for s in self.config.scope_files]
        else:
            files = list(self.repo_root.rglob("*.sol"))
        # Exclude
        out_of_scope = {str((self.repo_root / o).resolve()) for o in self.config.out_of_scope_files}
        out: list[Path] = []
        for f in files:
            try:
                resolved = f.resolve()
            except OSError:
                continue
            if not resolved.exists() or not resolved.is_file():
                continue
            if str(resolved) in out_of_scope:
                continue
            # Skip test files + node_modules / lib by convention
            rel = resolved.relative_to(self.repo_root)
            parts = rel.parts
            if any(p in ("node_modules", "lib", "out", "cache", "broadcast") for p in parts):
                continue
            if rel.name.endswith(".t.sol") or rel.name.endswith(".s.sol"):
                continue
            out.append(resolved)
        return out

    # ------------------------------------------------------------------
    # Per-file audit (parallel)
    # ------------------------------------------------------------------

    def _audit_files_parallel(self, files: list[Path]) -> list[LLMFinding]:
        if not files:
            return []
        workers = max(1, self.config.parallel_workers)
        out: list[LLMFinding] = []

        # If no LLM, run a no-op pipeline that still produces an empty
        # finding stream — keeps the rest of the orchestrator wired.
        if self.reasoner is None:
            logger.info("ContestOrchestrator: LLM disabled; skipping per-file LLM audit")
            self._files_scanned = len(files)
            return []

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self._audit_one_file, f): f for f in files}
            for fut in as_completed(futures):
                path = futures[fut]
                try:
                    findings = fut.result()
                except LLMProviderUnavailable:
                    logger.warning("LLM provider became unavailable mid-run")
                    break
                except Exception:
                    logger.exception("audit failed for %s", path)
                    continue
                self._files_scanned += 1
                if findings:
                    out.extend(findings)
                if self.cost_ledger.would_exceed_budget(projected_usd=0.5):
                    logger.warning("LLM budget exhausted; stopping further audits")
                    break
        return out

    def _audit_one_file(self, path: Path) -> list[LLMFinding]:
        assert self.reasoner is not None
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            logger.debug("could not read %s: %s", path, exc)
            return []
        # Build spec-claim summary scoped to this file.
        rel = str(path.relative_to(self.repo_root))
        file_claims = [c for c in self._spec_claims if rel in (c.source_location or "")]
        spec_summary = render_claims_for_prompt(file_claims, limit=20)
        invariant_summary = self._invariant_summary_for(path)
        return self.reasoner.audit_file(
            file_path=rel,
            source_code=source,
            graph_summary="",
            invariant_summary=invariant_summary,
            spec_claims_summary=spec_summary,
        )

    def _invariant_summary_for(self, path: Path) -> str:
        if not self.inferred_invariant_report:
            return ""
        name = path.stem
        rows = [
            inv for inv in self.inferred_invariant_report.invariants
            if name in (inv.contracts_involved or [])
        ]
        if not rows:
            return ""
        lines = []
        for inv in rows[:10]:
            lines.append(
                f"- [{inv.severity.value.upper() if hasattr(inv.severity, 'value') else inv.severity}] "
                f"{inv.type.value if hasattr(inv.type, 'value') else inv.type}: "
                f"{inv.description[:160]}"
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # PoC verification + contrarian
    # ------------------------------------------------------------------

    def _verify_and_review(
        self, findings: Iterable[LLMFinding],
    ) -> list[SubmissionFinding]:
        out: list[SubmissionFinding] = []
        for f in findings:
            sf = _llm_finding_to_submission(f, self.knowledge)
            sf.proof_of_concept_run_log = ""

            # PoC verification (optional)
            if (
                self.foundry_verifier is not None
                and self.config.use_foundry_verifier
                and f.proof_of_concept
                and "contract" in f.proof_of_concept.lower()
            ):
                try:
                    verifier_result = self.foundry_verifier.run(
                        test_code=f.proof_of_concept,
                        test_filename=f"ZeroPath_{f.file_path.replace('/', '_').replace('.', '_')}.t.sol",
                    )
                    sf.proof_of_concept_run_log = (
                        verifier_result.stdout[-2000:] if verifier_result.stdout else ""
                    )
                    if not verifier_result.ok:
                        # Downgrade confidence on broken PoCs but keep the finding —
                        # the underlying bug claim may still be valid.
                        sf.confidence = max(0.3, sf.confidence - 0.2)
                        sf.contrarian_objections.append(
                            f"PoC failed at stage={verifier_result.stage}: "
                            f"{verifier_result.error_summary}"
                        )
                except Exception:
                    logger.debug("foundry verifier crashed for %s", f.title)

            # Contrarian (LLM)
            if (
                self.config.use_contrarian
                and self.reasoner is not None
                and not self.cost_ledger.would_exceed_budget(projected_usd=0.2)
            ):
                try:
                    verdict = self.reasoner.contrarian_verdict(
                        finding_json=json.dumps({
                            "title": sf.title,
                            "severity": sf.severity,
                            "attack_class": sf.attack_class,
                            "description": sf.description,
                            "impact": sf.impact,
                            "attack_path": sf.attack_path,
                            "preconditions": sf.preconditions,
                            "proof_of_concept": sf.proof_of_concept_code,
                            "recommendation": sf.recommendation,
                            "confidence": sf.confidence,
                        }),
                        poc_run_log=sf.proof_of_concept_run_log,
                    )
                    if verdict.get("verdict") == "reject":
                        sf.contrarian_objections.extend(verdict.get("objections", []))
                        sf.confidence = max(0.0, sf.confidence - 0.3)
                    downgrade = verdict.get("downgrade_severity_to")
                    if downgrade and downgrade not in (None, "", "null"):
                        sf.severity = str(downgrade).lower()
                except Exception:
                    logger.debug("contrarian crashed for %s", sf.title)

            out.append(sf)
        return out

    # ------------------------------------------------------------------
    # Spec mismatch → SubmissionFinding
    # ------------------------------------------------------------------

    @staticmethod
    def _mismatches_as_findings(mismatches) -> list[SubmissionFinding]:
        out: list[SubmissionFinding] = []
        for m in mismatches:
            sev = m.claim.violation_severity
            out.append(SubmissionFinding(
                title=f"Spec/impl mismatch: {m.claim.claim[:80]}",
                severity=sev,
                attack_class="spec_violation",
                description=(
                    f"The documentation/NatSpec claims:\n\n> {m.claim.claim}\n\n"
                    f"but no Phase 2 invariant in the implementation enforces this. "
                    f"Manually verify whether the protocol actually enforces this "
                    f"property — spec/implementation gaps are frequent contest bugs."
                ),
                impact="Protocol behaviour may diverge from stated guarantees.",
                attack_path=[
                    "1. Identify the function the claim references.",
                    "2. Construct a transaction sequence that violates the claim.",
                    "3. Demonstrate the protocol does not revert / does not enforce the claim.",
                ],
                preconditions=[],
                proof_of_concept_code="",
                recommendation=(
                    "Either enforce the claim in code (modifier / invariant assertion) "
                    "or correct the documentation."
                ),
                confidence=0.55,
                spec_claim_source=m.claim.source,
                novelty_assessment=(
                    "Spec/impl gaps are easy for static auditors to miss because "
                    "they require reading prose docs in addition to code."
                ),
            ))
        return out

    # ------------------------------------------------------------------
    # Report assembly
    # ------------------------------------------------------------------

    def _build_report(
        self,
        prepared: list[Submission],
        scope_files: list[Path],
        elapsed: float,
    ) -> ContestReport:
        by_sev: dict[str, int] = {}
        for s in prepared:
            by_sev[s.finding.severity] = by_sev.get(s.finding.severity, 0) + 1

        ledger_summary = self.cost_ledger.summary()

        submitted_count = sum(
            1 for s in prepared
            if s.disposition in (
                SubmissionDisposition.SUBMIT_NOW, SubmissionDisposition.SUBMIT_LATER,
            )
        )
        discarded_count = sum(
            1 for s in prepared
            if s.disposition == SubmissionDisposition.DISCARD
        )
        return ContestReport(
            config=self.config,
            submissions=prepared,
            files_scanned=self._files_scanned or len(scope_files),
            raw_findings_count=len(self._raw_findings),
            valid_findings_count=sum(1 for s in prepared if s.finding.title),
            submitted_count=submitted_count,
            discarded_count=discarded_count,
            findings_by_severity=by_sev,
            llm_spent_usd=ledger_summary["spent_usd"],
            llm_calls=ledger_summary["calls"],
            elapsed_seconds=elapsed,
            ended_at=None,
            analysis_metadata={
                "platform": self.config.platform.value,
                "llm_provider": (
                    self.llm_provider.name if self.llm_provider else None
                ),
                "llm_model": (
                    self.llm_provider.model if self.llm_provider else None
                ),
                "llm_available": (
                    self.llm_provider.is_available if self.llm_provider else False
                ),
                "foundry_available": (
                    self.foundry_verifier.is_available
                    if self.foundry_verifier else False
                ),
                "knowledge_attached": self.knowledge is not None,
                "spec_claims_extracted": len(self._spec_claims),
                "scope_files": len(scope_files),
            },
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _llm_finding_to_submission(
    f: LLMFinding, knowledge: Optional[KnowledgeGraphOrchestrator],
) -> SubmissionFinding:
    historical: list[dict] = []
    if knowledge is not None:
        try:
            # Cheap hypothesis-shaped lookup
            from zeropath.adversarial.models import (
                AttackClass, AttackHypothesis,
            )
            try:
                cls = AttackClass(f.attack_class)
            except ValueError:
                cls = AttackClass.UNKNOWN
            hypo = AttackHypothesis(
                invariant_id="contest", invariant_description=f.root_cause,
                attack_class=cls, title=f.title, proposed_by="LLMReasoner",
                attack_narrative=f.root_cause,
                contracts_involved=list(f.contracts_involved),
            )
            _boost, matches = knowledge.lookup_historical_grounding(hypo)
            for inc in matches[:5]:
                historical.append({
                    "protocol": inc.protocol,
                    "incident_date": inc.incident_date,
                    "loss_usd": inc.loss_usd,
                    "source": inc.source.value if hasattr(inc.source, "value") else str(inc.source),
                    "source_url": inc.source_url,
                })
        except Exception:
            historical = []
    return SubmissionFinding(
        title=f.title,
        severity=(f.severity or "medium").lower(),
        attack_class=(f.attack_class or "other").lower(),
        contracts_involved=list(f.contracts_involved),
        functions_involved=list(f.functions_involved),
        lines_of_code=list(f.lines_of_code),
        description=f.root_cause,
        impact=f.impact,
        attack_path=list(f.attack_path),
        preconditions=list(f.preconditions),
        proof_of_concept_code=f.proof_of_concept,
        recommendation=f.recommendation,
        confidence=float(f.confidence or 0.5),
        historical_precedents=historical,
        novelty_assessment=f.novelty_assessment,
    )
