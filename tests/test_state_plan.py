from zeropath.core.schemas import CandidateFinding, Impact, ProjectConfig, SourceLocation
from zeropath.core.state_plan import build_candidate_state_plan
from zeropath.core.storage import Storage


def test_build_candidate_state_plan_persists_snapshot_and_status(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    storage.save_candidate(
        CandidateFinding(
            id="ZP-012",
            project_id="demo",
            title="Oracle candidate",
            status="hypothesis",
            protocol_type="lending",
            bug_class="oracle_stale_or_manipulated_price",
            attacker_model="Untrusted borrower",
            required_state=["Oracle price can be stale"],
            transaction_sequence=["prepare stale price", "borrow against mispriced collateral"],
            affected_contracts=["LendingPool"],
            root_cause_locations=[
                SourceLocation(file="src/Lending.sol", contract="LendingPool", line_start=42)
            ],
            impact=Impact(impact_type="bad_debt", funds_at_risk=True, explanation="demo"),
            tags=["oracle", "lending"],
        )
    )

    plan = build_candidate_state_plan(storage, "ZP-012")

    assert plan.candidate_id == "ZP-012"
    assert plan.artifact_path
    assert "oracle fixture, mocked feed, or forked oracle state" in plan.missing_dependencies
    assert "collateral/debt position fixture" in plan.suggested_fixtures
    assert storage.load_record("state_plan", "ZP-012")["candidate_id"] == "ZP-012"
    assert storage.load_candidate("ZP-012").status == "state_planned"
    assert (storage.zp_dir / "artifacts/snapshots/state_plan_ZP_012.json").exists()


def test_build_candidate_state_plan_can_run_without_persisting(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    storage.save_candidate(
        CandidateFinding(
            id="ZP-013",
            project_id="demo",
            title="Draft candidate",
            required_state=["victim deposit exists"],
            impact=Impact(impact_type="direct_theft", funds_at_risk=True, explanation="demo"),
        )
    )

    plan = build_candidate_state_plan(storage, "ZP-013", persist=False)

    assert plan.artifact_path is None
    assert storage.load_record("state_plan", "ZP-013") is None
    assert storage.load_candidate("ZP-013").status == "hypothesis"
