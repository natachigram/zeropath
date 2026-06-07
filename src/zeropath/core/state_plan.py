"""State planning for candidate proof work."""

from __future__ import annotations

import json
import re
from pathlib import Path

from zeropath.core.evidence import missing_evidence
from zeropath.core.schemas import CandidateFinding, CandidateStatePlan
from zeropath.core.storage import Storage


EARLY_STATUSES = {"observation", "hypothesis", "path_identified", "needs_evidence"}


def build_candidate_state_plan(
    storage: Storage,
    candidate_id: str,
    *,
    persist: bool = True,
) -> CandidateStatePlan:
    """Build and optionally persist a concrete proof-state plan."""

    candidate = storage.load_candidate(candidate_id)
    if candidate is None:
        raise KeyError(f"Candidate not found: {candidate_id}")

    plan = CandidateStatePlan(
        candidate_id=candidate.id,
        project_id=candidate.project_id,
        title=candidate.title,
        required_state=list(candidate.required_state),
        setup_steps=_setup_steps(candidate),
        transaction_steps=_transaction_steps(candidate),
        missing_dependencies=_missing_dependencies(candidate),
        evidence_to_collect=missing_evidence(candidate.evidence),
        suggested_fixtures=_suggested_fixtures(candidate),
        confidence=_confidence(candidate),
        notes=[
            "State plan is a proof worklist, not proof.",
            "Complete fixtures, execute the transaction path, and rerun judge before reporting.",
        ],
    )

    if persist:
        relative_path = Path("snapshots") / f"state_plan_{_safe_id(candidate.id)}.json"
        path = (storage.zp_dir / "artifacts" / relative_path).resolve()
        plan.artifact_path = str(path)
        storage.append_artifact(
            relative_path,
            json.dumps(plan.model_dump(mode="json"), indent=2, sort_keys=True),
            overwrite=True,
        )
        storage.save_record("state_plan", candidate.id, plan)
        if candidate.status in EARLY_STATUSES:
            candidate.status = "state_planned"
            candidate.evidence.notes.append(f"State plan written to {path}")
            storage.save_candidate(candidate)
    return plan


def _setup_steps(candidate: CandidateFinding) -> list[str]:
    steps: list[str] = []
    if candidate.attacker_model:
        steps.append(f"Create attacker actor matching model: {candidate.attacker_model}")
    else:
        steps.append("Define the untrusted attacker actor and capabilities.")
    steps.append("Create victim/user actors and seed balances needed for value assertions.")

    contracts = candidate.affected_contracts or [
        loc.contract for loc in candidate.root_cause_locations if loc.contract
    ]
    for contract in sorted(set(contracts)):
        steps.append(f"Deploy or load fixture for affected contract: {contract}")

    for item in candidate.required_state:
        steps.append(f"Materialize required state: {item}")

    if not candidate.required_state:
        steps.append("Define the reachable pre-state that makes the hypothesis executable.")
    return _dedupe(steps)


def _transaction_steps(candidate: CandidateFinding) -> list[str]:
    if not candidate.transaction_sequence:
        return ["Define the transaction sequence needed to trigger the candidate."]
    return [f"{idx + 1}. {step}" for idx, step in enumerate(candidate.transaction_sequence)]


def _missing_dependencies(candidate: CandidateFinding) -> list[str]:
    text = _combined_text(candidate)
    missing: list[str] = []
    if not candidate.root_cause_locations:
        missing.append("root cause source location")
    if not (candidate.affected_contracts or candidate.root_cause_locations):
        missing.append("target contract fixture or deployed address")
    if not candidate.evidence.live_config_checked and candidate.evidence.chain_id is None:
        missing.append("chain/fork block or documented local-only configuration")
    if not candidate.evidence.poc_path:
        missing.append("PoC artifact path")
    if not (candidate.impact.measured or candidate.evidence.profit_measured):
        missing.append("impact assertion and measured profit/loss bound")
    if "oracle" in text:
        missing.append("oracle fixture, mocked feed, or forked oracle state")
    if any(term in text for term in ("vault", "erc4626", "share")):
        missing.append("underlying asset fixture and share/accounting assertions")
    if any(term in text for term in ("lending", "liquidat", "collateral", "debt")):
        missing.append("collateral, debt, price, and liquidation configuration")
    if any(term in text for term in ("reward", "staking", "stake")):
        missing.append("reward token, reward index, and balance-change fixtures")
    if any(term in text for term in ("bridge", "message", "chain", "domain")):
        missing.append("source/destination domain and message replay fixture")
    return _dedupe(missing)


def _suggested_fixtures(candidate: CandidateFinding) -> list[str]:
    text = _combined_text(candidate)
    fixtures = ["attacker and victim actors", "protocol contract fixture", "token balances"]
    if "oracle" in text:
        fixtures.append("oracle price feed fixture")
    if any(term in text for term in ("vault", "erc4626", "share")):
        fixtures.append("underlying ERC20 asset and share accounting fixture")
    if any(term in text for term in ("lending", "liquidat", "collateral", "debt")):
        fixtures.append("collateral/debt position fixture")
    if any(term in text for term in ("reward", "staking", "stake")):
        fixtures.append("reward accrual fixture")
    if any(term in text for term in ("bridge", "message", "domain")):
        fixtures.append("cross-domain message fixture")
    return _dedupe(fixtures)


def _confidence(candidate: CandidateFinding) -> str:
    if candidate.evidence.state_preconditions_present and candidate.evidence.attacker_path_present:
        return "source_backed"
    if candidate.required_state and candidate.transaction_sequence:
        return "inferred"
    return "speculation"


def _combined_text(candidate: CandidateFinding) -> str:
    return " ".join(
        [
            candidate.title,
            candidate.protocol_type or "",
            candidate.bug_class or "",
            candidate.affected_invariant or "",
            " ".join(candidate.tags),
            " ".join(candidate.required_state),
            " ".join(candidate.transaction_sequence),
            candidate.notes,
        ]
    ).lower()


def _safe_id(candidate_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", candidate_id)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out
