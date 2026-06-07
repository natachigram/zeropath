from zeropath.core.candidates import generate_candidates, update_candidate_evidence
from zeropath.core.schemas import CandidateFinding, Impact, ProjectConfig
from zeropath.core.storage import Storage


def test_candidate_generation_and_lifecycle_update(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    storage.save_record(
        "ingest",
        "evm_index",
        {
            "protocol_type": "vault",
            "signals": ["asset_accounting"],
            "contracts": [{"name": "Vault", "file": "src/Vault.sol"}],
            "functions": [
                {"name": "deposit", "contract": "Vault", "file": "src/Vault.sol", "line_start": 10},
                {"name": "withdraw", "contract": "Vault", "file": "src/Vault.sol", "line_start": 20},
                {"name": "totalAssets", "contract": "Vault", "file": "src/Vault.sol", "line_start": 30},
            ],
            "raw_signal_text": ["balanceOf totalAssets deposit withdraw"],
        },
    )

    candidates = generate_candidates(storage, mode="critical", limit=5)

    assert len(candidates) == 1
    assert [candidate.id for candidate in candidates] == ["ZP-001"]
    assert candidates[0].status == "hypothesis"
    updated = storage.update_candidate_status(candidates[0].id, "rejected", "no reachable state")
    assert updated.status == "rejected"


def test_candidate_generation_uses_sequential_ids(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    storage.save_record(
        "ingest",
        "evm_index",
        {
            "protocol_type": "lending",
            "signals": ["oracle", "upgradeable"],
            "contracts": [{"name": "Vault", "file": "src/Vault.sol"}],
            "functions": [
                {"name": "borrow", "contract": "Vault", "file": "src/Vault.sol", "line_start": 10},
                {"name": "liquidate", "contract": "Vault", "file": "src/Vault.sol", "line_start": 20},
                {"name": "initialize", "contract": "Vault", "file": "src/Vault.sol", "line_start": 30},
            ],
            "raw_signal_text": [
                "oracle latestRoundData price borrow liquidate collateral healthFactor threshold closeFactor initialize"
            ],
        },
    )

    candidates = generate_candidates(storage, mode="critical", limit=5)

    assert [candidate.id for candidate in candidates] == ["ZP-001", "ZP-002", "ZP-003"]


def test_update_candidate_evidence_records_triage_and_score_inputs(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    storage.save_candidate(
        CandidateFinding(
            id="ZP-010",
            project_id="demo",
            title="Candidate",
            impact=Impact(impact_type="direct_theft", funds_at_risk=True, explanation="demo"),
        )
    )

    updated = update_candidate_evidence(
        storage,
        "ZP-010",
        root_cause_lines_present=True,
        attacker_path_present=True,
        state_preconditions_present=True,
        duplicate_risk="low",
        known_issue_risk="none",
        chain_id=1,
        fork_block=19_000_000,
        profit_measured=True,
        amount="1 ether",
        notes=["source lines reviewed"],
    )

    assert updated.evidence.root_cause_lines_present is True
    assert updated.evidence.attacker_path_present is True
    assert updated.evidence.state_preconditions_present is True
    assert updated.evidence.duplicate_risk_checked is True
    assert updated.evidence.known_issues_checked is True
    assert updated.evidence.live_config_checked is True
    assert updated.evidence.profit_measured is True
    assert updated.impact.measured is True
    assert updated.impact.amount == "1 ether"
    assert updated.duplicate_risk == "low"
    assert updated.known_issue_risk == "none"
    assert "source lines reviewed" in updated.evidence.notes
    assert storage.load_candidate("ZP-010").evidence.chain_id == 1
