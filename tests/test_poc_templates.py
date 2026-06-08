from zeropath.adapters.evm.poc_templates import render_foundry_poc
from zeropath.core.schemas import CandidateFinding, CandidateStatePlan, Impact


def test_foundry_poc_renders_state_plan_sections():
    candidate = CandidateFinding(
        id="ZP-020",
        project_id="demo",
        title="Planned PoC",
        attacker_model="Untrusted depositor",
        impact=Impact(impact_type="direct_theft", funds_at_risk=True, explanation="demo"),
    )
    plan = CandidateStatePlan(
        candidate_id="ZP-020",
        project_id="demo",
        title="Planned PoC",
        setup_steps=["Deploy Vault", "Seed victim balance"],
        transaction_steps=["1. attacker deposits", "2. victim deposits"],
        missing_dependencies=["underlying asset fixture"],
        evidence_to_collect=["measured impact/profit"],
        suggested_fixtures=["underlying ERC20 asset and share accounting fixture"],
        confidence="inferred",
        artifact_path=".zeropath/artifacts/snapshots/state_plan_ZP_020.json",
    )

    rendered = render_foundry_poc(candidate, state_plan=plan)

    assert "State plan: .zeropath/artifacts/snapshots/state_plan_ZP_020.json" in rendered
    assert "Plan confidence: inferred" in rendered
    assert "Suggested fixtures" in rendered
    assert "underlying asset fixture" in rendered
    assert "TODO: Deploy Vault" in rendered
    assert "TODO: 1. attacker deposits" in rendered


def test_foundry_poc_renders_entrypoint_call_hints():
    candidate = CandidateFinding(
        id="ZP-021",
        project_id="demo",
        title="Entrypoint PoC",
        attacker_model="Untrusted caller",
        entrypoints=["deposit(uint256,address)", "redeem(uint256,address,address)", "claim"],
        impact=Impact(impact_type="direct_theft", funds_at_risk=True, explanation="demo"),
    )

    rendered = render_foundry_poc(candidate)

    assert "Entrypoint call hints" in rendered
    assert "TODO: vm.prank(attacker); protocol.deposit(amount, victim);" in rendered
    assert "TODO: vm.prank(attacker); protocol.redeem(amount, victim, victim);" in rendered
    assert "TODO: vm.prank(attacker); protocol.claim();" in rendered
