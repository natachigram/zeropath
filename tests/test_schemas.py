from zeropath.core.schemas import (
    AdapterDetection,
    CandidateFinding,
    CandidateStatePlan,
    EvidenceBundle,
    Impact,
    ProjectConfig,
    SourceLocation,
)


def test_core_schemas_construct_and_serialize(tmp_path):
    config = ProjectConfig(
        project_id="demo",
        root_path=str(tmp_path),
        adapter="evm",
    )
    candidate = CandidateFinding(
        id="ZP-001",
        project_id=config.project_id,
        title="Demo candidate",
        root_cause_locations=[SourceLocation(file="src/Vault.sol", line_start=10)],
        impact=Impact(impact_type="direct_theft", funds_at_risk=True, explanation="demo"),
        evidence=EvidenceBundle(root_cause_lines_present=True),
    )
    detection = AdapterDetection(adapter="evm", confidence="medium", reasons=["solidity"])
    plan = CandidateStatePlan(candidate_id="ZP-001", project_id="demo", title="Plan")

    assert config.model_dump(mode="json")["adapter"] == "evm"
    assert candidate.model_dump(mode="json")["impact"]["funds_at_risk"] is True
    assert plan.model_dump(mode="json")["candidate_id"] == "ZP-001"
    assert detection.files_detected == []
