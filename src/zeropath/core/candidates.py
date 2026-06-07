"""Template-driven candidate lifecycle."""

from __future__ import annotations

import re

from zeropath.core.schemas import CandidateFinding, EvidenceBundle, Impact, SourceLocation
from zeropath.core.storage import Storage


def generate_candidates(
    storage: Storage,
    *,
    mode: str = "critical",
    limit: int = 5,
    focus: str | None = None,
) -> list[CandidateFinding]:
    """Generate structured hypotheses from adapter signals."""

    config = storage.load_project_config()
    index = storage.load_record("ingest", "evm_index") or {}
    protocol_type = (index.get("protocol_type") or "unknown").lower()
    candidates: list[CandidateFinding] = []
    titles_seen = {candidate.title for candidate in storage.list_candidates()}
    next_number = _next_candidate_number(storage)

    for template in _templates(index, protocol_type, mode, focus):
        if template["title"] in titles_seen:
            continue
        candidate = CandidateFinding(
            id=f"ZP-{next_number:03d}",
            project_id=config.project_id,
            title=template["title"],
            severity_guess=template.get("severity_guess"),
            protocol_type=template.get("protocol_type") or protocol_type,
            bug_class=template.get("bug_class"),
            affected_invariant=template.get("affected_invariant"),
            attacker_model=template.get("attacker_model"),
            entrypoints=template.get("entrypoints", []),
            affected_contracts=template.get("affected_contracts", []),
            root_cause_locations=template.get("root_cause_locations", []),
            required_state=template.get("required_state", []),
            transaction_sequence=template.get("transaction_sequence", []),
            impact=template.get("impact"),
            evidence=EvidenceBundle(
                notes=[
                    "Generated as a hypothesis from adapter signals.",
                    "Do not report until proof and judge checks pass.",
                ]
            ),
            duplicate_risk="unknown",
            known_issue_risk="unknown",
            tags=template.get("tags", []),
            notes=template.get("notes", ""),
        )
        storage.save_candidate(candidate)
        candidates.append(candidate)
        next_number += 1
        if len(candidates) >= limit:
            break
    return candidates


def _next_candidate_number(storage: Storage) -> int:
    highest = 0
    for candidate in storage.list_candidates():
        match = re.match(r"ZP-(\d+)", candidate.id)
        if match:
            highest = max(highest, int(match.group(1)))
    return highest + 1


def _templates(index: dict, protocol_type: str, mode: str, focus: str | None) -> list[dict]:
    signals = set(index.get("signals", []))
    function_names = {f.get("name", "").lower() for f in index.get("functions", [])}
    text = " ".join(index.get("raw_signal_text", [])).lower()
    contracts = [c.get("name", "") for c in index.get("contracts", []) if c.get("name")]
    templates: list[dict] = []

    if _allowed(mode, "high") and protocol_type in {"vault", "erc4626"}:
        has_vault_paths = {"deposit", "withdraw"} & function_names or {"mint", "redeem"} & function_names
        has_assets = "totalassets" in function_names or "balanceof" in text
        has_virtual = "virtual" in text or "dead shares" in text or "decimals offset" in text
        if has_vault_paths and has_assets and not has_virtual:
            loc = _first_location(index, {"deposit", "mint", "withdraw", "redeem", "totalAssets"})
            templates.append(
                _candidate_template(
                    title="Vault share accounting may be inflation-sensitive",
                    bug_class="erc4626_share_inflation",
                    protocol_type="vault",
                    invariant="INV-VLT-001",
                    severity="high",
                    attacker="Untrusted depositor able to donate assets or manipulate first-deposit accounting.",
                    required=[
                        "Vault has low or zero share supply.",
                        "Attacker can alter asset/share ratio before a victim deposit.",
                        "Victim deposit mints fewer shares than expected.",
                    ],
                    sequence=[
                        "Attacker seeds or donates assets to skew share price.",
                        "Victim deposits into skewed vault state.",
                        "Attacker redeems inflated share of withdrawable assets.",
                    ],
                    impact=Impact(
                        impact_type="direct_theft",
                        funds_at_risk=True,
                        explanation="Potential theft of later depositor assets if share accounting is manipulable.",
                    ),
                    locations=[loc] if loc else [],
                    entrypoints=["deposit", "mint", "withdraw", "redeem"],
                    contracts=contracts,
                    tags=["evm", "vault", "erc4626", "hypothesis"],
                )
            )

    if _allowed(mode, "high") and ("oracle" in signals or "oracle" in text or "latestrounddata" in text):
        value_sensitive = {"borrow", "liquidate", "mint", "redeem", "deposit", "withdraw"} & function_names
        has_guard = any(term in text for term in ("heartbeat", "stale", "sequencer", "updatedat", "maxdelay"))
        if value_sensitive and not has_guard:
            loc = _first_location(index, {"latestRoundData", "getPrice", "price", "borrow", "liquidate"})
            templates.append(
                _candidate_template(
                    title="Value-sensitive oracle path may lack freshness or manipulation checks",
                    bug_class="oracle_stale_or_manipulated_price",
                    protocol_type=protocol_type,
                    invariant="INV-ORACLE-001",
                    severity="high",
                    attacker="Untrusted user able to trigger value-sensitive accounting while oracle data is stale or manipulable.",
                    required=[
                        "Oracle output can be stale, invalid, or economically manipulable.",
                        "Protocol uses the price for minting, borrowing, redemption, or liquidation.",
                        "No effective freshness, bounds, or sequencer guard blocks the path.",
                    ],
                    sequence=[
                        "Prepare stale/manipulated oracle condition.",
                        "Call value-sensitive entrypoint using the bad price.",
                        "Extract value, bad debt, or unfair liquidation outcome.",
                    ],
                    impact=Impact(
                        impact_type="oracle_manipulation",
                        funds_at_risk=True,
                        explanation="Bad prices can misprice collateral, shares, liquidations, or mint/redeem amounts.",
                    ),
                    locations=[loc] if loc else [],
                    entrypoints=list(value_sensitive),
                    contracts=contracts,
                    tags=["evm", "oracle", "hypothesis"],
                )
            )

    if _allowed(mode, "high") and (protocol_type in {"staking/rewards", "rewards", "staking"} or "reward" in text):
        has_index = any(term in text for term in ("rewardpertoken", "accreward", "rewarddebt", "index"))
        balance_paths = {"transfer", "mint", "burn", "stake", "unstake"} & function_names
        if has_index and balance_paths:
            loc = _first_location(index, {"claim", "stake", "unstake", "transfer", "reward"})
            templates.append(
                _candidate_template(
                    title="Reward index may desynchronize across balance-changing paths",
                    bug_class="reward_index_desync",
                    protocol_type="staking/rewards",
                    invariant="INV-REWARD-001",
                    severity="high",
                    attacker="Untrusted user able to move stake or balances through paths with inconsistent reward index updates.",
                    required=[
                        "Reward index/debt accounting exists.",
                        "At least one balance-changing path can execute without equivalent reward synchronization.",
                        "Attacker can compare paths to claim unearned rewards.",
                    ],
                    sequence=[
                        "Accrue rewards under one balance state.",
                        "Move or update balance through a desynchronized path.",
                        "Claim rewards exceeding actual accrual.",
                    ],
                    impact=Impact(
                        impact_type="direct_theft",
                        funds_at_risk=True,
                        explanation="Unsynchronized rewards can drain reward funds or overpay an attacker.",
                    ),
                    locations=[loc] if loc else [],
                    entrypoints=list(balance_paths | {"claim"}),
                    contracts=contracts,
                    tags=["evm", "rewards", "hypothesis"],
                )
            )

    if _allowed(mode, "high") and (protocol_type == "lending" or "liquidate" in function_names):
        if "liquidate" in function_names and any(term in text for term in ("healthfactor", "ltv", "threshold", "closefactor", "collateral")):
            loc = _first_location(index, {"liquidate", "healthFactor", "threshold", "closeFactor"})
            templates.append(
                _candidate_template(
                    title="Liquidation threshold or close-factor transitions may create bad debt",
                    bug_class="liquidation_threshold_transition",
                    protocol_type="lending",
                    invariant="INV-LEND-002",
                    severity="high",
                    attacker="Liquidator or borrower able to exploit threshold ordering, oracle values, or close-factor branch transitions.",
                    required=[
                        "Account health changes around liquidation threshold.",
                        "Liquidation math has partial/full liquidation branches or close factors.",
                        "A branch transition can leave bad debt or overpay collateral.",
                    ],
                    sequence=[
                        "Prepare account near threshold.",
                        "Trigger liquidation branch with crafted repay/collateral values.",
                        "Observe bad debt, excess collateral seizure, or solvency break.",
                    ],
                    impact=Impact(
                        impact_type="bad_debt",
                        funds_at_risk=True,
                        explanation="Incorrect liquidation transitions can create bad debt or steal collateral.",
                    ),
                    locations=[loc] if loc else [],
                    entrypoints=["liquidate"],
                    contracts=contracts,
                    tags=["evm", "lending", "liquidation", "hypothesis"],
                )
            )

    if _allowed(mode, "high") and ("upgradeable" in signals or "initialize" in function_names):
        has_initializer_guard = "initializer" in text or "_disableinitializers" in text or "onlyinitializing" in text
        if "initialize" in function_names and not has_initializer_guard:
            loc = _first_location(index, {"initialize"})
            templates.append(
                _candidate_template(
                    title="Initializer access control may be reachable after deployment",
                    bug_class="access_control_initializer",
                    protocol_type=protocol_type,
                    invariant="INV-GEN-001",
                    severity="high",
                    attacker="Untrusted address able to call an unprotected initializer on an implementation or proxy.",
                    required=[
                        "Initializer remains callable in deployed configuration.",
                        "Initializer sets owner/admin/role or value-sensitive config.",
                        "Deployment path does not disable initializers.",
                    ],
                    sequence=[
                        "Find deployed implementation or proxy with callable initializer.",
                        "Call initialize as attacker.",
                        "Use acquired authority for fund-impacting action.",
                    ],
                    impact=Impact(
                        impact_type="unauthorized_mint",
                        funds_at_risk=True,
                        explanation="Initializer takeover can become critical only if reachable deployment state grants fund-impacting authority.",
                    ),
                    locations=[loc] if loc else [],
                    entrypoints=["initialize"],
                    contracts=contracts,
                    tags=["evm", "access-control", "initializer", "hypothesis"],
                )
            )
    if focus:
        focus_l = focus.lower()
        templates = [t for t in templates if focus_l in t["title"].lower() or focus_l in " ".join(t["tags"]).lower()]
    return templates


def _candidate_template(
    *,
    title: str,
    bug_class: str,
    protocol_type: str,
    invariant: str,
    severity: str,
    attacker: str,
    required: list[str],
    sequence: list[str],
    impact: Impact,
    locations: list[SourceLocation],
    entrypoints: list[str],
    contracts: list[str],
    tags: list[str],
) -> dict:
    return {
        "title": title,
        "bug_class": bug_class,
        "protocol_type": protocol_type,
        "affected_invariant": invariant,
        "severity_guess": severity,
        "attacker_model": attacker,
        "required_state": required,
        "transaction_sequence": sequence,
        "impact": impact,
        "root_cause_locations": locations,
        "entrypoints": entrypoints,
        "affected_contracts": contracts,
        "tags": tags,
        "notes": "Hypothesis only. Requires source confirmation, state planning, proof, duplicate checks, and judge approval.",
    }


def _allowed(mode: str, severity: str) -> bool:
    mode = mode.lower()
    if mode == "critical":
        return severity in {"critical", "high"}
    if mode == "high-medium":
        return severity in {"critical", "high", "medium"}
    return True


def _first_location(index: dict, names: set[str]) -> SourceLocation | None:
    lowered = {name.lower() for name in names}
    for fn in index.get("functions", []):
        if fn.get("name", "").lower() in lowered:
            return SourceLocation(
                file=fn.get("file", ""),
                contract=fn.get("contract"),
                function=fn.get("name"),
                line_start=fn.get("line_start"),
                line_end=fn.get("line_end"),
                description="Heuristic signal location; not yet proof.",
            )
    for contract in index.get("contracts", []):
        if contract.get("name", "").lower() in lowered:
            return SourceLocation(
                file=contract.get("file", ""),
                contract=contract.get("name"),
                line_start=contract.get("line_start"),
                description="Heuristic signal location; not yet proof.",
            )
    return None
