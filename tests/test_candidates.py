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


def test_bridge_replay_double_mint_candidate_requires_message_and_value_signals(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    storage.save_record(
        "ingest",
        "evm_index",
        {
            "protocol_type": "bridge",
            "signals": ["asset_accounting"],
            "contracts": [{"name": "DestinationBridge", "file": "src/DestinationBridge.sol"}],
            "functions": [
                {
                    "name": "receiveMessage",
                    "contract": "DestinationBridge",
                    "file": "src/DestinationBridge.sol",
                    "line_start": 42,
                },
                {
                    "name": "mint",
                    "contract": "DestinationBridge",
                    "file": "src/DestinationBridge.sol",
                    "line_start": 57,
                },
            ],
            "raw_signal_text": [
                "bridge receiveMessage sourceChain destinationChain domain nonce payload mint wrapped token"
            ],
        },
    )

    candidates = generate_candidates(storage, mode="critical", limit=5)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.title == "Bridge message execution may allow replayed mint or release"
    assert candidate.bug_class == "bridge_message_replay_double_mint"
    assert candidate.affected_invariant == "INV-BRIDGE-001"
    assert candidate.severity_guess == "critical"
    assert candidate.impact.funds_at_risk is True
    assert candidate.impact.impact_type == "unauthorized_mint"
    assert "receiveMessage" in candidate.entrypoints
    assert "mint" in candidate.entrypoints
    assert candidate.root_cause_locations[0].function == "receiveMessage"
    assert any("same message" in item for item in candidate.required_state)
    assert any("Replay" in item for item in candidate.transaction_sequence)
    assert {"bridge", "replay", "double-mint", "hypothesis"} <= set(candidate.tags)


def test_bridge_replay_candidate_does_not_spam_guarded_or_non_value_bridge(tmp_path):
    guarded = Storage(tmp_path / "guarded")
    guarded.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    guarded.save_record(
        "ingest",
        "evm_index",
        {
            "protocol_type": "bridge",
            "signals": ["asset_accounting"],
            "contracts": [{"name": "DestinationBridge", "file": "src/DestinationBridge.sol"}],
            "functions": [
                {"name": "receiveMessage", "contract": "DestinationBridge", "file": "src/DestinationBridge.sol"},
                {"name": "mint", "contract": "DestinationBridge", "file": "src/DestinationBridge.sol"},
            ],
            "raw_signal_text": [
                "bridge receiveMessage messageId sourceChain nonce mint processedMessages replayProtection"
            ],
        },
    )
    generic = Storage(tmp_path / "generic")
    generic.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    generic.save_record(
        "ingest",
        "evm_index",
        {
            "protocol_type": "bridge",
            "signals": [],
            "contracts": [{"name": "BridgeRouter", "file": "src/BridgeRouter.sol"}],
            "functions": [
                {"name": "sendMessage", "contract": "BridgeRouter", "file": "src/BridgeRouter.sol"},
                {"name": "quoteFee", "contract": "BridgeRouter", "file": "src/BridgeRouter.sol"},
            ],
            "raw_signal_text": ["bridge sendMessage destinationChain nonce payload fee quote"],
        },
    )

    assert generate_candidates(guarded, mode="critical", limit=5) == []
    assert generate_candidates(generic, mode="critical", limit=5) == []


def test_governance_takeover_candidate_requires_executable_fund_impact(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    storage.save_record(
        "ingest",
        "evm_index",
        {
            "protocol_type": "governance",
            "signals": ["asset_accounting"],
            "contracts": [{"name": "Governor", "file": "src/Governor.sol"}],
            "functions": [
                {"name": "propose", "contract": "Governor", "file": "src/Governor.sol", "line_start": 15},
                {"name": "castVote", "contract": "Governor", "file": "src/Governor.sol", "line_start": 30},
                {"name": "execute", "contract": "Governor", "file": "src/Governor.sol", "line_start": 50},
                {"name": "mint", "contract": "TreasuryToken", "file": "src/TreasuryToken.sol", "line_start": 12},
            ],
            "raw_signal_text": [
                "governance proposal quorum castVote balanceOf voting power execute targets values calldata treasury mint"
            ],
        },
    )

    candidates = generate_candidates(storage, mode="critical", limit=5)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.title == "Governance proposal execution may permit takeover with fund-impacting payload"
    assert candidate.bug_class == "governance_executable_takeover"
    assert candidate.affected_invariant == "INV-GOV-001"
    assert candidate.severity_guess == "critical"
    assert candidate.impact.funds_at_risk is True
    assert candidate.impact.impact_type == "governance_takeover"
    assert {"propose", "castVote", "execute", "mint"} <= set(candidate.entrypoints)
    assert candidate.root_cause_locations[0].function == "execute"
    assert any("funds" in item for item in candidate.required_state)
    assert any("Execute the proposal" in item for item in candidate.transaction_sequence)
    assert {"governance", "takeover", "fund-impact", "hypothesis"} <= set(candidate.tags)


def test_governance_takeover_candidate_does_not_spam_generic_or_guarded_governance(tmp_path):
    generic = Storage(tmp_path / "generic")
    generic.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    generic.save_record(
        "ingest",
        "evm_index",
        {
            "protocol_type": "governance",
            "signals": [],
            "contracts": [{"name": "Governor", "file": "src/Governor.sol"}],
            "functions": [
                {"name": "propose", "contract": "Governor", "file": "src/Governor.sol"},
                {"name": "castVote", "contract": "Governor", "file": "src/Governor.sol"},
                {"name": "execute", "contract": "Governor", "file": "src/Governor.sol"},
            ],
            "raw_signal_text": ["governance proposal quorum votes execute parameter update"],
        },
    )
    guarded = Storage(tmp_path / "guarded")
    guarded.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    guarded.save_record(
        "ingest",
        "evm_index",
        {
            "protocol_type": "governance",
            "signals": ["asset_accounting"],
            "contracts": [{"name": "Governor", "file": "src/Governor.sol"}],
            "functions": [
                {"name": "propose", "contract": "Governor", "file": "src/Governor.sol"},
                {"name": "castVote", "contract": "Governor", "file": "src/Governor.sol"},
                {"name": "queue", "contract": "Governor", "file": "src/Governor.sol"},
                {"name": "execute", "contract": "Governor", "file": "src/Governor.sol"},
                {"name": "mint", "contract": "TreasuryToken", "file": "src/TreasuryToken.sol"},
            ],
            "raw_signal_text": [
                "governance proposal quorum getPastVotes checkpoint timelockController queue mint treasury"
            ],
        },
    )

    assert generate_candidates(generic, mode="critical", limit=5) == []
    assert generate_candidates(guarded, mode="critical", limit=5) == []


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
