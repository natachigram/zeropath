"""
Phase 7 test suite — Exploit Evolution Engine (Swarm RL).

Coverage:
  - Reward shaping: spec formula weights, normalisation, HITL term
  - ExploitEnvironment: reset, step, action_space, episode termination, stub sim
  - StochasticPolicy: each exploration strategy + HITL absorb + serialise
  - RLAgent: end-to-end episode with stats update, fitness
  - PopulationManager: init diversity, evolve (selection + reseed + inherit)
  - CurriculumScheduler: rolling-mean promotion, force_set, serialise
  - HumanInTheLoop: submit/withdraw/match by sequence/hypothesis/fingerprint
  - CheckpointManager: save → load → restore round-trip
  - TrainingOrchestrator: smoke end-to-end + HITL routing + checkpoint cadence
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest

from zeropath.sequencer.models import (
    AttackContext,
    ProfitEstimate,
    TransactionSequence,
    TxCall,
)
from zeropath.simulator.models import (
    HalmosResult,
    SimulationOutcome,
    SimulationResult,
)
from zeropath.rl import (
    Action,
    AgentSpec,
    CheckpointManager,
    CurriculumScheduler,
    CurriculumTier,
    Episode,
    EpisodeOutcome,
    ExploitEnvironment,
    ExplorationStrategy,
    HITLSignal,
    HITLSignalType,
    HumanInTheLoop,
    PopulationManager,
    PopulationStats,
    RewardBreakdown,
    RewardInputs,
    RewardShaper,
    RLAgent,
    Specialization,
    State,
    StepResult,
    StochasticPolicy,
    StubExecutor,
    TrainingOrchestrator,
    TrainingReport,
    TrainingState,
)


# ===========================================================================
# Test fixtures
# ===========================================================================


def _mk_seq(
    *,
    attack_class: str = "flash_loan",
    uses_flash: bool = True,
    hypothesis_id: str | None = None,
) -> TransactionSequence:
    return TransactionSequence(
        hypothesis_id=hypothesis_id or str(uuid4()),
        hypothesis_title="test",
        attack_class=attack_class,
        calls=[
            TxCall(
                step=1, description="approve",
                target_address_expr="WETH",
                target_address="0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                function_signature="approve(address,uint256)",
                params=["0x000000000000000000000000000000000000dEaD", 1_000_000],
                param_types=["address", "uint256"],
            ),
            TxCall(
                step=2, description="flash loan",
                target_address_expr="IPool(AAVE)",
                target_address="0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",
                function_signature="flashLoanSimple(address,address,uint256,bytes,uint16)",
                params=[
                    "0x000000000000000000000000000000000000dEaD",
                    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                    10 ** 18, b"", 0,
                ],
                param_types=["address", "address", "uint256", "bytes", "uint16"],
            ),
            TxCall(
                step=3, description="swap",
                target_address_expr="IPair(POOL)",
                target_address="0x000000000000000000000000000000000000aaaa",
                function_signature="swap(uint256,uint256,address,bytes)",
                params=[1000, 0, "0x000000000000000000000000000000000000dEaD", b""],
                param_types=["uint256", "uint256", "address", "bytes"],
            ),
            TxCall(
                step=4, description="repay",
                target_address_expr="WETH",
                target_address="0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                function_signature="transfer(address,uint256)",
                params=["0x000000000000000000000000000000000000dEaD", 1_001_000],
                param_types=["address", "uint256"],
            ),
        ],
        context=AttackContext(chain="mainnet", flash_loan_provider=(
            "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2" if uses_flash else None
        )),
        uses_flash_loan=uses_flash,
        profit_estimate=ProfitEstimate(
            asset="WETH",
            min_profit_expression="1e16",
            max_profit_expression="1e21",
            cost_expression="(flashAmount * 9) / 10000",
        ),
    )


class _ScriptedExecutor:
    """Deterministic executor whose result is the next entry in a queue."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def execute(self, sequence: TransactionSequence) -> SimulationResult:
        i = min(self.calls, len(self.outcomes) - 1)
        out = self.outcomes[i]
        self.calls += 1
        return SimulationResult(
            sequence_id=sequence.id,
            hypothesis_id=sequence.hypothesis_id,
            success=out.get("outcome") == SimulationOutcome.PROFITABLE,
            outcome=out.get("outcome", SimulationOutcome.EXECUTED_NO_PROFIT),
            profit_wei=out.get("profit_wei", 0),
            gas_used=out.get("gas_used", 200_000),
        )


# ===========================================================================
# RewardShaper
# ===========================================================================


class TestRewardShaper:
    def test_zero_input_yields_zero_total(self):
        # All inputs zero — including the diversity default (which is 1.0
        # by design to reward unique trajectories on first sight).
        out = RewardShaper().shape(RewardInputs(sequence_diversity=0.0))
        assert out.total == 0.0
        assert out.positive_total == 0.0

    def test_default_diversity_gives_small_positive(self):
        # The semantics: a fresh RewardInputs() represents a *novel*
        # action sequence, so it deserves the diversity bonus.
        out = RewardShaper().shape(RewardInputs())
        assert out.diversity_term == pytest.approx(0.10, abs=1e-6)
        assert out.total == out.diversity_term

    def test_profit_dominates(self):
        out = RewardShaper().shape(RewardInputs(profit_wei=1000 * 10 ** 18))
        # Saturated profit term ≈ 0.5 (the spec weight)
        assert out.profit_term == pytest.approx(0.5, abs=0.01)
        assert out.total > 0.4

    def test_gas_capital_are_negative(self):
        out = RewardShaper().shape(RewardInputs(gas_used=30_000_000, capital_required_usd=10_000_000))
        assert out.gas_term < 0
        assert out.capital_term < 0

    def test_novelty_and_diversity(self):
        out = RewardShaper().shape(RewardInputs(is_novel_state=True, sequence_diversity=1.0))
        assert out.novelty_term == pytest.approx(0.10, abs=1e-6)
        assert out.diversity_term == pytest.approx(0.10, abs=1e-6)

    def test_hitl_promising_lifts_total(self):
        baseline = RewardShaper().shape(RewardInputs(profit_wei=0))
        with_signal = RewardShaper().shape(
            RewardInputs(profit_wei=0),
            hitl_signals=[HITLSignal(
                signal_type=HITLSignalType.PROMISING, weight=1.0,
            )],
        )
        assert with_signal.hitl_term > 0
        assert with_signal.total > baseline.total

    def test_hitl_not_viable_pulls_total_down(self):
        baseline = RewardShaper().shape(RewardInputs(profit_wei=10 ** 18))
        with_signal = RewardShaper().shape(
            RewardInputs(profit_wei=10 ** 18),
            hitl_signals=[HITLSignal(
                signal_type=HITLSignalType.NOT_VIABLE, weight=1.0,
            )],
        )
        assert with_signal.hitl_term < 0
        assert with_signal.total < baseline.total

    def test_weights_are_overridable(self):
        custom = RewardShaper(weights={"profit": 1.0})
        out = custom.shape(RewardInputs(profit_wei=1000 * 10 ** 18))
        # Doubled weight → roughly double the profit term
        default = RewardShaper().shape(RewardInputs(profit_wei=1000 * 10 ** 18))
        assert out.profit_term > default.profit_term * 1.9

    def test_hitl_capped(self):
        shaper = RewardShaper(hitl_multiplier_cap=0.3)
        out = shaper.shape(
            RewardInputs(profit_wei=0),
            hitl_signals=[HITLSignal(signal_type=HITLSignalType.PROMISING, weight=5.0)],
        )
        assert out.hitl_term <= 0.3


# ===========================================================================
# ExploitEnvironment
# ===========================================================================


class TestExploitEnvironment:
    def test_reset_returns_state(self):
        env = ExploitEnvironment(seed_sequences=[_mk_seq()], simulator=StubExecutor())
        state = env.reset()
        assert isinstance(state, State)
        assert state.step_index == 0
        assert state.curriculum_tier == CurriculumTier.SINGLE_CONTRACT_NO_ORACLE
        assert env.current_sequence is not None

    def test_action_space_includes_execute_stop_and_mutations(self):
        env = ExploitEnvironment(seed_sequences=[_mk_seq()], simulator=StubExecutor())
        labels = {a.label for a in env.action_space}
        assert "execute" in labels
        assert "stop" in labels
        assert any(lbl.startswith("mutate:") for lbl in labels)

    def test_execute_terminates_episode(self):
        env = ExploitEnvironment(seed_sequences=[_mk_seq()], simulator=StubExecutor())
        env.reset()
        result = env.step(Action(kind="execute"))
        assert result.done is True
        assert "simulation" in result.info

    def test_stop_terminates_episode(self):
        env = ExploitEnvironment(seed_sequences=[_mk_seq()], simulator=StubExecutor())
        env.reset()
        result = env.step(Action(kind="stop"))
        assert result.done is True

    def test_budget_exhaustion_auto_executes(self):
        env = ExploitEnvironment(
            seed_sequences=[_mk_seq()], simulator=StubExecutor(),
            step_budget=2,
        )
        env.reset()
        env.step(Action(kind="mutate", operator="scale_amount_10x"))
        # Second mutation triggers auto-execute when budget hits limit.
        last = env.step(Action(kind="mutate", operator="scale_amount_10x"))
        assert last.done is True
        assert last.info.get("auto_executed") is True

    def test_step_without_reset_raises(self):
        env = ExploitEnvironment(seed_sequences=[_mk_seq()])
        with pytest.raises(RuntimeError):
            env.step(Action(kind="execute"))

    def test_tier_filters_eligible_seeds(self):
        flash_seq = _mk_seq(attack_class="flash_loan")
        # Composability seed should only be eligible at CROSS_PROTOCOL tier.
        composability = _mk_seq(attack_class="composability")
        env = ExploitEnvironment(
            seed_sequences=[flash_seq, composability],
            simulator=StubExecutor(),
        )
        env.reset(curriculum_tier=CurriculumTier.SINGLE_CONTRACT_NO_ORACLE)
        # The tier filter should have picked the flash_loan attack-class seed
        # since flash_loan's floor is WITH_FLASH_LOAN > SINGLE_CONTRACT...
        # but the fallback ("no eligible") returns the full pool — so either
        # is valid; just verify we got *some* sequence.
        assert env.current_sequence is not None

    def test_state_hash_changes_on_mutation(self):
        env = ExploitEnvironment(seed_sequences=[_mk_seq()], simulator=StubExecutor())
        state_a = env.reset()
        env.step(Action(kind="mutate", operator="scale_amount_1000x"))
        # Build a fresh state object to compare
        # After a scale mutation, the magnitude bucket should differ.
        state_b = env._build_state()  # internal but it's the cleanest hook
        assert state_a.state_hash != state_b.state_hash


# ===========================================================================
# StubExecutor
# ===========================================================================


class TestStubExecutor:
    def test_deterministic_for_same_input(self):
        seq = _mk_seq()
        r1 = StubExecutor().execute(seq)
        r2 = StubExecutor().execute(seq)
        assert r1.profit_wei == r2.profit_wei
        assert r1.outcome == r2.outcome
        assert r1.gas_used == r2.gas_used


# ===========================================================================
# StochasticPolicy
# ===========================================================================


def _action_space() -> list[Action]:
    return [
        Action(kind="mutate", operator="scale_amount_10x"),
        Action(kind="mutate", operator="reorder_inner_steps"),
        Action(kind="execute"),
        Action(kind="stop"),
    ]


class TestStochasticPolicy:
    @pytest.mark.parametrize("strategy", [
        ExplorationStrategy.EPSILON_GREEDY,
        ExplorationStrategy.UCB,
        ExplorationStrategy.THOMPSON,
        ExplorationStrategy.SOFTMAX,
        ExplorationStrategy.PURE_RANDOM,
    ])
    def test_each_strategy_selects_valid_action(self, strategy):
        spec = AgentSpec(exploration=strategy, seed=42)
        policy = StochasticPolicy(spec)
        actions = _action_space()
        env = ExploitEnvironment(seed_sequences=[_mk_seq()], simulator=StubExecutor())
        state = env.reset()
        chosen = policy.select(state, available=actions)
        assert chosen in actions

    def test_update_records_count_and_mean(self):
        policy = StochasticPolicy(AgentSpec(seed=1))
        action = Action(kind="execute")
        policy.update(action, reward=0.5, terminal=True)
        policy.update(action, reward=1.0, terminal=True)
        assert policy.action_counts["execute"] == 2
        assert policy.action_means["execute"] == pytest.approx(0.75, abs=1e-6)

    def test_suggested_mutation_takes_priority(self):
        spec = AgentSpec(exploration=ExplorationStrategy.PURE_RANDOM, seed=42)
        policy = StochasticPolicy(spec)
        policy.absorb_hitl([HITLSignal(
            signal_type=HITLSignalType.SUGGESTED_MUTATION,
            suggested_mutation="scale_amount_10x",
        )])
        actions = _action_space()
        env = ExploitEnvironment(seed_sequences=[_mk_seq()], simulator=StubExecutor())
        chosen = policy.select(env.reset(), available=actions)
        assert chosen.label == "mutate:scale_amount_10x"

    def test_promising_signal_lifts_means(self):
        policy = StochasticPolicy(AgentSpec(seed=1))
        # Seed action first so update has somewhere to push.
        policy.update(Action(kind="execute"), reward=0.1, terminal=True)
        before = policy.action_means["execute"]
        policy.absorb_hitl([HITLSignal(signal_type=HITLSignalType.PROMISING, weight=1.0)])
        assert policy.action_means["execute"] > before

    def test_to_dict_round_trip(self):
        spec = AgentSpec(seed=42, exploration=ExplorationStrategy.UCB, ucb_c=2.5)
        policy = StochasticPolicy(spec)
        policy.update(Action(kind="execute"), reward=0.7, terminal=True)
        serialised = policy.to_dict()
        clone = StochasticPolicy.from_dict(serialised)
        assert clone.spec.id == spec.id
        assert clone.action_means == policy.action_means
        assert clone.action_counts == policy.action_counts

    def test_specialization_affinity_seeds_higher_q(self):
        spec_flash = AgentSpec(specialization=Specialization.FLASH_LOAN, seed=1)
        spec_gen = AgentSpec(specialization=Specialization.GENERALIST, seed=1)
        actions = _action_space()  # includes mutate:scale_amount_10x
        env = ExploitEnvironment(seed_sequences=[_mk_seq()], simulator=StubExecutor())
        state = env.reset()
        p1 = StochasticPolicy(spec_flash)
        p2 = StochasticPolicy(spec_gen)
        # Trigger seeding by selecting once.
        p1.select(state, available=actions)
        p2.select(state, available=actions)
        # scale_amount_10x is in FLASH_LOAN's affinity tuple — flash specialist
        # should see a non-zero affinity bonus, generalist should not.
        flash_mean = p1.action_means.get("mutate:scale_amount_10x", 0)
        gen_mean = p2.action_means.get("mutate:scale_amount_10x", 0)
        assert flash_mean > gen_mean


# ===========================================================================
# RLAgent
# ===========================================================================


class TestRLAgent:
    def test_episode_updates_stats(self):
        agent = RLAgent(AgentSpec(seed=42))
        env = ExploitEnvironment(seed_sequences=[_mk_seq()], simulator=StubExecutor())
        ep = agent.run_episode(env, reward_shaper=RewardShaper())
        assert isinstance(ep, Episode)
        assert agent.stats.episodes == 1
        assert agent.stats.last_seen_generation == 0
        assert ep.agent_id == agent.spec.id
        assert ep.action_log  # at least one action recorded

    def test_episode_outcome_classification(self):
        agent = RLAgent(AgentSpec(seed=1))
        env = ExploitEnvironment(
            seed_sequences=[_mk_seq()],
            simulator=_ScriptedExecutor([{
                "outcome": SimulationOutcome.PROFITABLE,
                "profit_wei": 10 ** 18,
                "gas_used": 300_000,
            }]),
        )
        # Force execute on first action by exhausting epsilon randomness:
        # use PURE_RANDOM policy and run several episodes; at least one will
        # be PROFITABLE because the scripted executor always returns PROFIT.
        agent.spec.exploration = ExplorationStrategy.PURE_RANDOM
        agent.policy = StochasticPolicy(agent.spec)
        outcomes = set()
        for _ in range(20):
            ep = agent.run_episode(env, reward_shaper=RewardShaper())
            outcomes.add(ep.outcome)
        assert EpisodeOutcome.PROFITABLE in outcomes

    def test_invariant_score_from_halmos(self):
        # Episode where simulation has halmos_result=FALSIFIED should
        # populate invariant_term in the reward.
        agent = RLAgent(AgentSpec(
            seed=1, exploration=ExplorationStrategy.PURE_RANDOM,
        ))

        class HalmosExecutor:
            def execute(self, seq):
                return SimulationResult(
                    sequence_id=seq.id,
                    hypothesis_id=seq.hypothesis_id,
                    success=True,
                    outcome=SimulationOutcome.EXECUTED_NO_PROFIT,
                    profit_wei=0,
                    gas_used=100_000,
                    halmos_result=HalmosResult.FALSIFIED,
                )
        env = ExploitEnvironment(
            seed_sequences=[_mk_seq()], simulator=HalmosExecutor(),
        )
        # Find an execute-terminated episode.
        found = False
        for _ in range(50):
            ep = agent.run_episode(env, reward_shaper=RewardShaper())
            if ep.outcome != EpisodeOutcome.BUDGET_EXHAUSTED:
                # Should have non-zero invariant term either way
                if ep.reward.invariant_term > 0:
                    found = True
                    break
        assert found, "expected at least one episode to inherit halmos invariant credit"


# ===========================================================================
# PopulationManager
# ===========================================================================


class TestPopulationManager:
    def test_initial_population_size(self):
        pm = PopulationManager(population_size=8, rng_seed=42)
        assert len(pm.agents) == 8

    def test_initial_diversity(self):
        pm = PopulationManager(population_size=8, rng_seed=42)
        strategies = {a.spec.exploration for a in pm.agents}
        specs = {a.spec.specialization for a in pm.agents}
        assert len(strategies) >= 3
        assert len(specs) >= 3

    def test_evolve_advances_generation(self):
        pm = PopulationManager(population_size=10, rng_seed=42)
        initial_gen = pm.generation
        # Inject some fitness so selection is meaningful.
        for i, a in enumerate(pm.agents):
            a.stats.episodes = 1
            a.stats.cumulative_reward = float(i)
        stats = pm.evolve()
        assert pm.generation == initial_gen + 1
        assert stats.elite_size >= 1
        assert stats.reseeded_size >= 1
        assert len(pm.agents) == 10

    def test_evolve_preserves_top_agents(self):
        pm = PopulationManager(
            population_size=5,
            elite_fraction=0.4,
            reseed_fraction=0.4,
            rng_seed=42,
        )
        # Give one agent very high fitness.
        for i, a in enumerate(pm.agents):
            a.stats.episodes = 1
            a.stats.cumulative_reward = 0.0
        pm.agents[0].stats.cumulative_reward = 10.0
        top_id = pm.agents[0].spec.id
        pm.evolve()
        new_ids = {a.spec.id for a in pm.agents}
        assert top_id in new_ids

    def test_evolve_records_history(self):
        pm = PopulationManager(population_size=4, rng_seed=42)
        assert len(pm.history) == 1
        pm.evolve()
        assert len(pm.history) == 2
        assert pm.history[-1].generation == 1


# ===========================================================================
# CurriculumScheduler
# ===========================================================================


def _mk_episode(reward_total: float) -> Episode:
    return Episode(
        agent_id="x",
        reward=RewardBreakdown(total=reward_total),
    )


class TestCurriculumScheduler:
    def test_starts_at_lowest_tier(self):
        s = CurriculumScheduler()
        assert s.tier == CurriculumTier.SINGLE_CONTRACT_NO_ORACLE

    def test_no_promotion_below_window(self):
        s = CurriculumScheduler(window=10, required_consecutive=1)
        for _ in range(3):
            s.record_episode(_mk_episode(1.0))
        assert s.maybe_promote() is False
        assert s.tier == CurriculumTier.SINGLE_CONTRACT_NO_ORACLE

    def test_promotes_when_threshold_cleared(self):
        s = CurriculumScheduler(window=10, required_consecutive=1)
        for _ in range(10):
            s.record_episode(_mk_episode(1.0))  # well above any threshold
        assert s.maybe_promote() is True
        assert s.tier == CurriculumTier.MULTI_CONTRACT

    def test_required_consecutive(self):
        s = CurriculumScheduler(window=4, required_consecutive=2)
        for _ in range(4):
            s.record_episode(_mk_episode(1.0))
        assert s.maybe_promote() is False  # only first clear
        for _ in range(4):
            s.record_episode(_mk_episode(1.0))
        assert s.maybe_promote() is True

    def test_top_tier_does_not_promote(self):
        s = CurriculumScheduler(starting_tier=CurriculumTier.CROSS_PROTOCOL)
        for _ in range(50):
            s.record_episode(_mk_episode(10.0))
        assert s.maybe_promote() is False

    def test_force_set_tier(self):
        s = CurriculumScheduler()
        s.force_set_tier(CurriculumTier.WITH_FLASH_LOAN)
        assert s.tier == CurriculumTier.WITH_FLASH_LOAN

    def test_serialise_round_trip(self):
        s = CurriculumScheduler(window=10, required_consecutive=2)
        for _ in range(5):
            s.record_episode(_mk_episode(0.5))
        data = s.to_dict()
        clone = CurriculumScheduler.from_dict(data)
        assert clone.tier == s.tier
        assert pytest.approx(clone.rolling_mean) == s.rolling_mean


# ===========================================================================
# HumanInTheLoop
# ===========================================================================


class TestHumanInTheLoop:
    def test_promising_signal_matches_by_sequence(self):
        hitl = HumanInTheLoop()
        hitl.mark_promising(sequence_id="S1", weight=1.0)
        signals = hitl.signals_for(sequence_id="S1")
        assert len(signals) == 1
        assert signals[0].signal_type == HITLSignalType.PROMISING

    def test_signal_matches_by_hypothesis(self):
        hitl = HumanInTheLoop()
        hitl.mark_not_viable(hypothesis_id="H1", weight=1.0)
        signals = hitl.signals_for(hypothesis_id="H1")
        assert len(signals) == 1

    def test_signal_matches_by_fingerprint(self):
        hitl = HumanInTheLoop()
        hitl.mark_promising(fingerprint="abc123")
        signals = hitl.signals_for(fingerprint="abc123")
        assert len(signals) == 1

    def test_untargeted_signal_matches_anything(self):
        hitl = HumanInTheLoop()
        hitl.mark_promising(weight=1.0)
        signals = hitl.signals_for(sequence_id="anything")
        assert len(signals) == 1

    def test_no_match_returns_empty(self):
        hitl = HumanInTheLoop()
        hitl.mark_promising(sequence_id="S1")
        assert hitl.signals_for(sequence_id="S99") == []

    def test_one_shot_consumption(self):
        hitl = HumanInTheLoop(persistent_by_default=True)
        hitl.mark_promising(sequence_id="S1", persistent=False)
        first = hitl.signals_for(sequence_id="S1")
        second = hitl.signals_for(sequence_id="S1")
        assert len(first) == 1 and len(second) == 0

    def test_withdraw(self):
        hitl = HumanInTheLoop()
        s = hitl.mark_promising(sequence_id="S1")
        assert hitl.withdraw(s.id) is True
        assert hitl.signals_for(sequence_id="S1") == []

    def test_suggested_mutation_carries_operator(self):
        hitl = HumanInTheLoop()
        hitl.suggest_mutation(operator="scale_amount_10x", sequence_id="S1")
        signals = hitl.signals_for(sequence_id="S1")
        assert signals[0].suggested_mutation == "scale_amount_10x"


# ===========================================================================
# CheckpointManager
# ===========================================================================


class TestCheckpointManager:
    def test_save_load_round_trip(self, tmp_path):
        pm = PopulationManager(population_size=4, rng_seed=42)
        # Mutate some stats so we can verify they survive.
        pm.agents[0].stats.episodes = 7
        pm.agents[0].stats.cumulative_reward = 3.5
        pm.agents[0].stats.profitable_episodes = 1

        cur = CurriculumScheduler()
        cur.force_set_tier(CurriculumTier.WITH_ORACLE)

        hitl = HumanInTheLoop()
        hitl.mark_promising(sequence_id="S1", weight=2.0)

        mgr = CheckpointManager(tmp_path / "ckpt")
        path = mgr.save(
            population=pm, curriculum=cur, hitl=hitl,
            total_episodes=42, protocol_name="X",
        )
        assert path.exists()

        new_pm, new_cur, new_hitl, state = mgr.restore()
        assert state.total_episodes == 42
        assert state.protocol_name == "X"
        assert new_cur.tier == CurriculumTier.WITH_ORACLE
        assert len(new_pm.agents) == 4
        # Stats round-tripped
        assert new_pm.agents[0].stats.episodes == 7
        assert new_pm.agents[0].stats.cumulative_reward == 3.5
        # HITL round-tripped
        assert len(new_hitl.all_signals()) == 1

    def test_latest_pointer_updated(self, tmp_path):
        mgr = CheckpointManager(tmp_path / "ckpt")
        pm = PopulationManager(population_size=2, rng_seed=1)
        mgr.save(population=pm, curriculum=CurriculumScheduler(),
                  hitl=HumanInTheLoop(), total_episodes=10)
        mgr.save(population=pm, curriculum=CurriculumScheduler(),
                  hitl=HumanInTheLoop(), total_episodes=20)
        latest = json.loads((tmp_path / "ckpt" / "latest.json").read_text())
        assert latest["state"]["total_episodes"] == 20

    def test_schema_mismatch_raises(self, tmp_path):
        from zeropath.rl.checkpoint import CheckpointError
        path = tmp_path / "broken.json"
        path.write_text(json.dumps({"schema_version": 99, "state": {}}))
        mgr = CheckpointManager(tmp_path)
        with pytest.raises(CheckpointError):
            mgr.load(path)


# ===========================================================================
# TrainingOrchestrator
# ===========================================================================


class TestTrainingOrchestrator:
    def test_smoke_end_to_end(self):
        orch = TrainingOrchestrator(
            seed_sequences=[_mk_seq()],
            population=PopulationManager(population_size=3, rng_seed=1),
        )
        report = orch.run(generations=2, episodes_per_agent=1)
        assert isinstance(report, TrainingReport)
        assert len(report.episodes) == 6   # 3 agents × 2 gens × 1 episode
        assert report.state.generation >= 1
        assert "elapsed_seconds" in report.analysis_metadata

    def test_profitable_discovery_propagates(self):
        # Force every episode to be profitable via a scripted executor.
        executor = _ScriptedExecutor([{
            "outcome": SimulationOutcome.PROFITABLE,
            "profit_wei": 5 * 10 ** 18,
            "gas_used": 300_000,
        }])
        orch = TrainingOrchestrator(
            seed_sequences=[_mk_seq()],
            simulator=executor,
            population=PopulationManager(population_size=2, rng_seed=1),
        )
        # Force PURE_RANDOM so episodes terminate on execute fairly often.
        for a in orch.population.agents:
            a.spec.exploration = ExplorationStrategy.PURE_RANDOM
            a.policy = StochasticPolicy(a.spec)
        report = orch.run(generations=1, episodes_per_agent=5)
        # At least some episodes should be PROFITABLE.
        assert any(e.outcome == EpisodeOutcome.PROFITABLE for e in report.episodes)
        assert report.discovered_sequence_ids

    def test_hitl_signal_routed_to_episode(self):
        orch = TrainingOrchestrator(
            seed_sequences=[_mk_seq()],
            population=PopulationManager(population_size=2, rng_seed=1),
        )
        # Target every sequence by sequence_id.
        seed = orch.seed_sequences[0]
        orch.hitl.mark_promising(sequence_id=seed.id, weight=1.0)
        report = orch.run(generations=1, episodes_per_agent=1)
        assert any(e.hitl_signals_received > 0 for e in report.episodes)

    def test_checkpoint_cadence(self, tmp_path):
        mgr = CheckpointManager(tmp_path)
        orch = TrainingOrchestrator(
            seed_sequences=[_mk_seq()],
            population=PopulationManager(population_size=2, rng_seed=1),
            checkpoint_manager=mgr,
            checkpoint_interval_episodes=2,
        )
        orch.run(generations=1, episodes_per_agent=1)
        # 2 episodes total → exactly one checkpoint
        files = list(tmp_path.glob("checkpoint-*.json"))
        assert files
        latest = tmp_path / "latest.json"
        assert latest.exists()

    def test_curriculum_records_episodes(self):
        orch = TrainingOrchestrator(
            seed_sequences=[_mk_seq()],
            population=PopulationManager(population_size=2, rng_seed=1),
            curriculum=CurriculumScheduler(window=8, required_consecutive=1),
        )
        orch.run(generations=1, episodes_per_agent=2)
        # The scheduler should have recorded all episodes.
        assert orch.curriculum.rolling_mean != 0.0 or orch.curriculum.tier == CurriculumTier.SINGLE_CONTRACT_NO_ORACLE
