# ZeroPath: Autonomous Security Research System
## Full Phase Specification (Updated)

---

## Language Architecture

One language is not right for all phases. The stack is split by performance profile:

```
┌─────────────────────────────────────────────────────────────────┐
│  ANALYSIS LAYER  (Phases 1, 2, 3, 6, 8)                        │
│  Language: Python                                               │
│  Reason: Slither, PyTorch, LangChain, Neo4j driver.             │
│  Non-negotiable. Slither owns this layer.                       │
└─────────────────────────────┬───────────────────────────────────┘
                              │ JSON / gRPC / message queue
┌─────────────────────────────▼───────────────────────────────────┐
│  SIMULATION + EXECUTION LAYER  (Phases 4, 5)                    │
│  Language: Rust (native Foundry/Anvil) + Python subprocess      │
│  Reason: Foundry is Rust. EVM execution must be fast.           │
│  Anvil RPC lets Python orchestrate; Rust does the heavy work.   │
└─────────────────────────────┬───────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│  RL + TRAINING LAYER  (Phase 7)                                 │
│  Language: Python (PyTorch + RLlib / stable-baselines3)         │
│  Reason: No other language has this ML ecosystem.               │
└─────────────────────────────┬───────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│  API + SERVING LAYER  (productionization)                       │
│  Language: Go                                                   │
│  Reason: Concurrent job queues, low-latency API, easy deploy.   │
│  Python stays internal; Go faces the outside world.             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Swarm Intelligence Architecture (MiroFish-Inspired)

MiroFish (github.com/666ghj/MiroFish) is a multi-agent swarm intelligence engine
that uses GraphRAG + Neo4j + OASIS to simulate hundreds of autonomous agents and
produce emergent insights through collective behavior. It hit #1 GitHub trending in
March 2026 and was backed by $4.1M within 24 hours of launch.

Do NOT use MiroFish's codebase directly — it is a social prediction engine and is
non-deterministic. But its core architecture principle is directly applicable here:

  Multi-agent swarm + graph-grounded simulation produces qualitatively better
  emergent insights than single-model reasoning.

This principle is applied in ZeroPath in two places:

**Phase 3 — Adversarial Agent Swarm (replaces single LLM):**
Instead of one LLM generating attack hypotheses, run specialized adversarial agents
in parallel. Each agent is an expert in one attack class. A debate round surfaces
conflicts and produces ranked, diverse hypotheses. Single-LLM monoculture is eliminated.

**Phase 7 — Swarm + RL (augments PPO):**
A population of diverse RL agents with fitness-based selection explores the attack
sequence space orders of magnitude faster than a single PPO agent in a sparse reward
environment. MiroFish's 1M-agent design principle: more diverse agents = faster
emergent discovery of strategies the designer never anticipated.

**Phase 8 — GraphRAG for knowledge graph construction:**
MiroFish uses GraphRAG (Microsoft) + Neo4j for multi-level knowledge graph
construction with subgraph querying. Phase 8 is building exactly this. Use
GraphRAG directly instead of a custom implementation.

---

## PHASE 1: Protocol Ingestion + Graph Builder

### Goal

Turn smart contracts into a structured protocol graph.
Without this, everything else is blind.

### What you are building

- Solidity parser
- Vyper parser (Curve, Yearn, Lido vault components are Vyper — Slither supports it)
- AST extractor
- call graph builder
- storage layout extractor
- basic asset flow tracking
- proxy / upgradeable contract detector
- bytecode-mode fallback (decompiler integration for unverified contracts)

### Critical additions vs. original spec

**Proxy pattern detection (non-negotiable):**
Transparent proxies, UUPS, Beacon proxies are the most exploited pattern in DeFi.
They have different storage layouts and delegatecall chains. Slither has built-in
proxy detection — use it. Without this, you are blind to the majority of real targets.

**Bytecode-mode fallback:**
Most real-world targets do not publish verified source. When source is unavailable,
integrate Heimdall-rs or Dedaub API to decompile bytecode and produce a degraded but
useful protocol graph. The system must not hard-fail on unverified contracts.

**Vyper support:**
Slither supports Vyper. Add a language detection step before parsing. The parser
should dispatch to the correct Slither backend based on file extension and pragma.

**Version diff analysis:**
Accept two versions of a protocol (v1 path, v2 path) and produce a diff graph:
new functions, changed state variables, new external dependencies. Protocol upgrades
are where the most impactful bugs live.

### Output

```json
{
  "contracts": [],
  "functions": [],
  "calls": [],
  "state_variables": [],
  "external_dependencies": [],
  "proxy_relationships": [],
  "storage_layout": {},
  "language": "solidity|vyper|unknown",
  "source_available": true,
  "version_diff": {}
}
```

### LLM Prompt (Phase 1)

You are a senior blockchain infrastructure engineer.

Build a production-grade Python service that ingests Solidity and Vyper smart
contracts and constructs a structured protocol graph.

Requirements:

- Use the latest stable Python version and modern best practices.
- Use Slither as the primary analysis backend for both Solidity and Vyper.
- Design the system as a modular service with clear separation between:
  ingestion, analysis, graph construction
- Extract the following:
  - contract names, language, compiler version
  - functions (public, external, internal, constructor, fallback, receive)
  - function call graph (who calls what, including cross-contract)
  - state variables (type, visibility, storage slot)
  - modifiers and access control patterns
  - external calls (including low-level calls, delegatecall, staticcall)
  - proxy relationships (transparent, UUPS, Beacon)
  - upgradeable contract detection
- When source code is unavailable, fall back to bytecode decompilation via
  Heimdall-rs (subprocess) and produce a degraded graph with a source_available: false flag.
- Build a graph representation:
  - nodes: contracts, functions, variables, external protocols
  - edges: calls, reads, writes, delegates, inherits
- Support version diff mode: compare two versions of a protocol and output delta graph.
- Store results in JSON format and persist into Neo4j.
- Include a CLI interface:
  - input: path to contracts, directory, GitHub repo URL, or contract address + chain
  - output: JSON + graph DB insert
- Ensure the system handles large codebases efficiently (multiprocessing, not threads).

Deliver: clean architecture, type-safe code, logging, error handling, unit tests,
integration test against a real Solidity file.

Do not simplify. Build as if this will be used in a real security research system.

---

## PHASE 2: Invariant Inference Engine

### Goal

Automatically infer what must never break.
This is where you start thinking like an auditor.

### What you are building

- detect value flows
- infer balance relationships
- detect share accounting patterns
- identify permission boundaries
- cross-protocol composability invariant detection
- known-exploit-grounded invariant library (RAG from DeFiHackLabs / Rekt / Immunefi)
- price oracle dependency mapping

### Critical additions vs. original spec

**Cross-protocol composability invariants:**
The most dangerous DeFi attacks are multi-protocol: Protocol A's price oracle,
B's flash loan, C's AMM, composed in a single transaction. Your invariant engine
must analyze protocols in the context of what they depend on, not in isolation.
Map external_dependencies from Phase 1 to known protocol interfaces and infer
cross-boundary invariants.

**Known-exploit grounding via RAG:**
Every invariant class you can infer has already been broken in production.
DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs), Rekt.news, and Immunefi
post-mortems are ground truth. Use RAG over this database to:
  - anchor inferred invariants to real historical violations
  - assign higher confidence to invariants matching known exploit patterns
  - attach "historical precedent" metadata to each invariant

**Price oracle dependency detection:**
Identify all functions that read external price data. Map the oracle source
(Chainlink, Uniswap TWAP, custom). Flag single-block oracle reads as
manipulation-vulnerable. This is a Phase 2 output, not Phase 3.

**Formal invariant output:**
In addition to natural language descriptions, output invariants in a
machine-checkable format compatible with Halmos/Certora for Phase 5 use:

```
forall tx: balanceBefore(protocol) >= balanceAfter(protocol) - deposited(tx)
```

### Output

```json
{
  "type": "value_conservation",
  "description": "...",
  "formal_spec": "...",
  "confidence": 0.0-1.0,
  "historical_precedent": [{"protocol": "...", "loss_usd": 0, "rekt_url": "..."}],
  "oracle_dependencies": [],
  "cross_protocol_scope": ["protocolA", "protocolB"]
}
```

### LLM Prompt (Phase 2)

You are a smart contract security researcher and AI systems engineer.

Build a Python module that takes a protocol graph as input and infers likely invariants.

Requirements:

- Input: graph structure from Phase 1.
- Detect common DeFi patterns:
  - deposit/withdraw flows
  - mint/burn patterns
  - lending/borrowing relationships
  - AMM liquidity management
  - governance vote execution
- Infer invariants including:
  - conservation of value
  - balance consistency
  - collateralization relationships
  - oracle manipulation resistance
  - cross-protocol composability boundaries
- For each invariant, query a RAG index of DeFiHackLabs / Rekt / Immunefi reports
  to find historical violations of the same class. Attach as metadata.
- Detect all price oracle dependencies. Flag single-block reads.
- Use heuristics + rule-based logic. No ML yet.
- Output invariants with formal spec strings (Halmos-compatible where possible).
- Design the system to support multiple hypotheses per invariant.
- Include confidence scoring. Boost confidence when historical precedent exists.

Bonus: pluggable invariant detectors, cross-protocol invariant inference.

Focus on correctness and extensibility. Avoid naive pattern matching.

---

## PHASE 3: Attack Hypothesis Generator (Adversarial Swarm)

### Goal

Turn invariants into attack ideas.
Use a swarm of specialized adversarial agents, not a single LLM.

### What you are building

- Adversarial multi-agent swarm (MiroFish architecture applied to security)
- Agent types: each is an expert in one attack class
- Debate round: agents challenge each other's proposals
- Consensus ranking: ranked, diverse, validated hypotheses
- Exploit template library: known attack patterns as structured templates

### Why swarm, not single LLM

A single LLM reasoning about attack vectors converges to the same blind spots every
time. It produces monoculture thinking. An adversarial swarm eliminates this:

```
OracleManipulatorAgent  → "can the price feed be moved in one block?"
ReentrancyAgent         → "is there state change after external call?"
AccessControlAgent      → "can this role be obtained without authorization?"
FlashLoanAgent          → "can atomicity bypass this balance check?"
ComposabilityAgent      → "can another protocol's state be weaponized here?"
GovernanceAttackAgent   → "can a vote be passed and executed atomically?"
```

Each agent runs independently in parallel (asyncio). A debate round surfaces
conflicts. A consensus layer produces final ranked hypotheses. This is directly
inspired by MiroFish's emergent multi-agent dynamics — applied adversarially
to security research instead of social prediction.

### Output

```json
{
  "invariant": "...",
  "attack_vector": "...",
  "attack_class": "reentrancy|oracle|flash_loan|access_control|composability|governance",
  "required_conditions": [],
  "potential_profit_mechanism": "...",
  "exploit_template": "...",
  "agent_consensus_score": 0.0-1.0,
  "dissenting_agents": [],
  "confidence": 0-1
}
```

### LLM Prompt (Phase 3)

You are building a system that generates attack hypotheses from inferred invariants
using a swarm of specialized adversarial AI agents.

Requirements:

- Input: protocol graph + inferred invariants from Phase 2.
- Instantiate one agent per attack class:
  oracle manipulation, reentrancy, access control bypass, flash loan atomicity,
  cross-protocol composability, governance attack, integer math exploitation.
- Each agent receives the full protocol graph and a target invariant.
- Each agent independently generates hypotheses using step-by-step adversarial reasoning.
- Run all agents in parallel via asyncio.
- Run a debate round (3 rounds): agents review and challenge each other's hypotheses.
  An agent may upgrade its confidence or withdraw a hypothesis based on peer critique.
- A consensus agent aggregates results, deduplicates, and ranks by:
  - agent agreement score
  - specificity (concrete > vague)
  - historical precedent match (from Phase 2 metadata)
- Filter: reject any hypothesis that cannot be expressed as a concrete, testable
  transaction sequence. Vague hypotheses are dropped, not softened.
- Output ranked hypotheses with dissenting agent notes preserved.

Every hypothesis must be concrete, testable, and non-redundant.
Design this as a reusable adversarial reasoning engine.

---

## PHASE 4: Transaction Sequence Generator (MEV-style)

### Goal

Convert attack ideas into real executable sequences.

### What you are building

- sequence generator
- mutation engine
- parameter exploration
- on-chain state integration (real mainnet state at a specific block)
- cross-protocol composability sequencing
- calldata encoder / ABI encoder

### Critical additions vs. original spec

**On-chain state integration (non-negotiable):**
Exploit sequences need real mainnet state: pool reserves, oracle prices, liquidity
depth, collateral ratios at a specific block. Without this, generated sequences are
synthetic and may be un-executable on a real fork. Integrate with an Ethereum RPC
(Alchemy, Infura, or local node) to fetch live state before sequence generation.

**Cross-protocol composability:**
Attacks that span multiple protocols in a single transaction are the most profitable.
The sequence generator must support multi-protocol call chains:
fetch price from protocol A → manipulate via protocol B → exploit protocol C → repay.

**Gas optimization:**
Include a gas estimator. Sequences that cost more gas than the potential profit
are invalid and should be pruned early, not after simulation.

### Output

```json
[
  {
    "action": "call",
    "contract": "",
    "function": "",
    "params": [],
    "value_wei": 0,
    "expected_state_change": {},
    "gas_estimate": 0
  }
]
```

Metadata:
```json
{
  "block_number": 0,
  "fork_url": "...",
  "total_gas_estimate": 0,
  "estimated_profit_wei": 0,
  "uses_flash_loan": true,
  "protocols_touched": []
}
```

### LLM Prompt (Phase 4)

You are a DeFi MEV engineer.

Build a transaction sequence generator for exploit discovery.

Requirements:

- Input: attack hypothesis + protocol graph + live on-chain state (fetched via RPC).
- Fetch real mainnet state at a specified block before generating sequences.
  Use web3.py or ethers to get pool reserves, oracle prices, collateral ratios.
- Generate sequences of contract interactions:
  function calls, parameter sets, ETH values, calldata
- Include mutation strategies:
  reorder calls, vary amounts, repeat actions, substitute protocols
- Encode all calldata correctly using ABI encoding. Sequences must be
  directly executable — not pseudocode.
- Include gas estimates per step. Prune sequences where total_gas > estimated_profit.
- Include support for: flash loans, token swaps, oracle updates, governance execution.
- Support multi-protocol sequences (cross-contract composability attacks).
- Design for extensibility. New protocol adapters should be pluggable.

Focus on generating diverse, realistic, and immediately executable attack sequences.

---

## PHASE 5: EVM Simulation Engine

### Goal

Execute sequences in real conditions.

### What you are building

- Foundry integration (forge + anvil)
- mainnet fork execution
- state tracking
- fuzzing integration (Echidna / Medusa)
- symbolic execution path (Halmos)
- revert analysis

### Critical additions vs. original spec

**Fuzzing integration:**
Foundry simulation and fuzzing are complementary, not alternatives. Foundry executes
targeted sequences. Echidna/Medusa discovers property violations through random
input generation. Both run against the same fork. Fuzzer targets invariants from
Phase 2; simulator targets sequences from Phase 4.

**Symbolic execution:**
Integrate Halmos for invariant verification. For each Phase 2 invariant that has a
formal_spec, run Halmos to check whether it is formally provable or falsifiable.
This is more rigorous than simulation for coverage of all possible inputs.

**Revert analysis:**
When a sequence fails (reverts), capture the full revert reason, the call stack at
revert, and the state delta up to the revert point. Feed this back to Phase 4 as
mutation guidance: "failed at step 3 because allowance was insufficient — try
approve() before transferFrom()."

### Output

```json
{
  "success": true,
  "profit_wei": 0,
  "profit_usd": 0,
  "state_diff": {},
  "events_emitted": [],
  "gas_used": 0,
  "revert_reason": null,
  "revert_call_stack": [],
  "fuzzer_violations": [],
  "halmos_result": "proved|falsified|unknown",
  "block_number": 0,
  "fork_url": ""
}
```

### LLM Prompt (Phase 5)

You are a blockchain systems engineer.

Build a simulation engine using Foundry that executes generated transaction sequences.

Requirements:

- Use Foundry (forge + anvil). Foundry is Rust — interface via Anvil JSON-RPC.
  Python orchestrates via web3.py against the Anvil RPC endpoint.
- Support mainnet forking at a specified block number.
- Execute sequences programmatically. Parse results from Anvil RPC responses.
- Capture: balances before and after, state storage diffs, events emitted, gas used.
- On revert: capture full revert reason and call stack. Return structured revert info
  as mutation feedback for Phase 4.
- Integrate Echidna or Medusa for property-based fuzzing. Run fuzzers against
  Phase 2 invariants on the same fork.
- Integrate Halmos for formal invariant checking. Run against Phase 2 formal_spec
  strings where available.
- Ensure reproducibility: same block number + same sequence = same result, always.
- Return structured results that Phase 6 can validate and Phase 7 can learn from.

This must be robust and production-ready. No flaky infrastructure.

---

## PHASE 6: Exploit Validation Engine

### Goal

Kill false positives.

### What you are building

- profit validation
- permission checks
- realism checks
- severity scoring (CVSS-style)
- duplicate detection
- second-opinion adversarial review

### Critical additions vs. original spec

**Severity scoring:**
A valid exploit is not binary. Score on multiple dimensions:
  - profit magnitude (low / medium / high / critical)
  - capital required (flash loan = $0 upfront vs. requires $10M)
  - time sensitivity (exploitable now vs. requires specific market conditions)
  - stealth (can it be front-run by MEV bots before the attacker?)
  - reversibility (can the protocol pause and recover?)

**Duplicate detection:**
As the system matures, it will find the same vulnerability multiple ways.
Deduplicate validated exploits against Phase 8 knowledge graph before surfacing.
Do not report the same root cause twice.

**Second-opinion adversarial review:**
After validation passes, run one contrarian agent whose only job is to find reasons
the exploit will fail in practice. This agent looks for: MEV competition, gas limit
issues, liquidity assumptions, admin key mitigations. If it cannot invalidate the
exploit, confidence goes up.

### Output

```json
{
  "valid": true,
  "reason": "...",
  "confidence": 0-1,
  "severity": {
    "profit_tier": "low|medium|high|critical",
    "capital_required_usd": 0,
    "requires_flash_loan": true,
    "time_sensitive": false,
    "mev_frontrunnable": false,
    "protocol_pausable": false
  },
  "duplicate_of": null,
  "contrarian_objections": [],
  "recommended_action": "report|simulate_further|discard"
}
```

### LLM Prompt (Phase 6)

You are a senior smart contract auditor.

Build an exploit validation module.

Requirements:

- Input: simulation results from Phase 5 + attack hypothesis from Phase 3.
- Validate: profit > 0, no privileged roles required, realistic liquidity assumptions.
- Score severity across: profit tier, capital required, time sensitivity, MEV
  frontrunability, protocol pausability.
- Check Phase 8 knowledge graph for duplicates. If same root cause found before,
  flag as duplicate with reference.
- Run a second-opinion contrarian agent: its only job is to find practical failure
  modes. It checks: MEV competition, gas limits, liquidity depth, admin mitigations,
  sandwich risk. If it cannot invalidate, confidence increases.
- Reject false positives aggressively. When in doubt, reject.
- Output structured results that feed both Phase 7 (learning signal) and
  Phase 8 (knowledge graph storage).

Focus on skepticism, correctness, and actionable severity scoring.

---

## PHASE 7: Exploit Evolution Engine (Swarm RL)

### Goal

Discover new attack strategies automatically.

### What you are building

- Swarm of diverse RL agents (population-based, not single PPO)
- shaped reward function (not sparse)
- fitness-based selection across agents
- curriculum learning (simple protocols first)
- human-in-the-loop guidance interface

### Critical additions vs. original spec

**Sparse reward problem:**
PPO with a single reward signal (profit > 0) in this environment will fail to explore
effectively. The reward is too delayed — most trajectories end in zero profit.
The agent learns to do nothing. Fix with reward shaping:

```
reward = (
    profit_wei * 0.5
  + invariant_violation_score * 0.3    # partial credit for finding violations
  + novel_state_coverage * 0.1         # reward for visiting new states
  + sequence_diversity_bonus * 0.1     # penalize repeating the same calls
  - gas_cost * 0.05
  - capital_required * 0.05
)
```

**Population-based swarm (MiroFish architecture):**
Run a population of N agents (N=50-500 depending on compute budget) with different:
  - exploration strategies (epsilon-greedy vs. UCB vs. Thompson sampling)
  - specializations (one focuses on flash loans, one on oracle manipulation, etc.)
  - random seeds

Use fitness-based selection: top K agents reproduce (share policy weights), bottom K
are re-initialized with mutations. This is genetic algorithm + RL combined. The swarm
explores the attack sequence space orders of magnitude faster than a single agent.

**Curriculum learning:**
Start training on simple protocols (single-contract, no oracles). Graduate to complex
protocols only after the agent demonstrates competence. Prevents the agent from being
permanently confused by protocol complexity early in training.

**Human-in-the-loop:**
Provide an interface for a security researcher to:
  - mark a discovered sequence as "promising" (positive reward injection)
  - mark a sequence as "not viable" (negative reward injection)
  - suggest a new mutation to try
This allows domain expertise to guide exploration without replacing it.

### LLM Prompt (Phase 7)

You are an AI research engineer specializing in reinforcement learning.

Build a swarm-based reinforcement learning system for evolving exploit strategies.

Requirements:

- Define environment:
  - state: protocol graph + current EVM state (from Phase 5 fork)
  - actions: transaction sequences (from Phase 4 generator)
  - reward: shaped reward (profit + invariant violation + novelty - gas - capital)
- Run a population of N diverse RL agents simultaneously.
  Each agent has a different specialization and exploration strategy.
  Use fitness-based selection: top performers share weights, bottom are re-seeded.
- Implement curriculum learning: train on simple protocols first, gate progression
  on performance thresholds.
- Use PPO or SAC as base RL algorithm within each agent.
- Integrate human-in-the-loop: accept researcher reward signals for promising sequences.
- Integrate with Phase 5 simulation engine for environment feedback.
- Allow continuous training. Checkpoint regularly. Support resume from checkpoint.
- Feed discovered exploits back to Phase 8 knowledge graph.

Focus on stability, scalability, and sample efficiency. The sparse reward problem
must be explicitly addressed through reward shaping and population diversity.

---

## PHASE 8: Knowledge Graph + Memory System (GraphRAG)

### Goal

Make the system learn over time. Build institutional memory.

### What you are building

- exploit database
- pattern matching
- similarity detection
- GraphRAG-based knowledge graph construction
- feedback loop into hypothesis generation
- temporal pattern analysis (attacks after upgrades)
- external threat intelligence integration

### Critical additions vs. original spec

**GraphRAG for knowledge graph construction:**
MiroFish validated this at scale: GraphRAG (Microsoft) + Neo4j produces multi-level
graph summaries that enable both global queries ("what protocol type is most vulnerable
to oracle attacks?") and local queries ("which functions in this contract match the
pattern of the Euler Finance hack?"). Use GraphRAG directly here instead of a
custom implementation. Its multi-level summarization reduces LLM context requirements
for agent queries in Phase 3.

**Temporal pattern analysis:**
Track when vulnerabilities were introduced relative to protocol upgrades.
The pattern "upgrade → new vulnerability within 30 days" is a real signal.
Store version diff data from Phase 1 and correlate with exploit discovery timestamps.

**External threat intelligence:**
Ingest and normalize data from:
  - DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)
  - Rekt.news
  - Immunefi post-mortems
  - Chainalysis on-chain attribution data (where available)
Store as first-class graph nodes. Every inferred invariant and validated exploit
should be linked to relevant historical incidents.

**Feedback loop quality measurement:**
Track prediction accuracy over time:
  - invariants inferred in Phase 2 → were they actually violated later?
  - attack hypotheses in Phase 3 → were they validated in Phase 6?
  - RL-discovered sequences → which generalized to new protocols?

This measurement loop is what separates a memory system from a database.

### LLM Prompt (Phase 8)

You are a systems architect specializing in knowledge graphs and long-term learning systems.

Build a knowledge graph system for exploit intelligence using GraphRAG + Neo4j.

Requirements:

- Use Microsoft GraphRAG for multi-level knowledge graph construction.
  Configure global summaries (exploit pattern classes), local summaries (per-protocol),
  and motif detection (recurring vulnerability structures).
- Store in Neo4j:
  - exploit patterns (with attack class, TVL impact, root cause)
  - invariants broken (linked to protocols and historical incidents)
  - protocol structures (from Phase 1 graph)
  - temporal relationships (upgrade → vulnerability → exploit timeline)
- Ingest external threat intelligence:
  DeFiHackLabs, Rekt.news, Immunefi reports. Normalize to a common schema.
  Link external incidents to internal protocol graph nodes where protocols match.
- Implement similarity queries:
  - find protocols with similar graph structures to known-hacked protocols
  - find invariants matching the class of a historical exploit
  - find exploit sequences similar to previously validated ones (deduplication)
- Enable feedback loop: Phase 3 agents query this graph before generating hypotheses.
  Confidence of hypotheses matching historical patterns is boosted automatically.
- Track prediction accuracy: log every inference made and whether it was validated.
  Surface accuracy metrics per attack class and per protocol type.

Design for long-term learning. The system should be measurably smarter after
analyzing 100 protocols than after analyzing 1.

---

## PHASE 9: Audit Report Generator (New)

### Goal

Turn machine-readable findings into human-readable security reports.
This is what converts the research system into a product.

### What you are building

- structured finding formatter
- severity ranking and deduplication
- remediation suggestion engine
- PDF / Markdown report generator
- CI/CD integration (GitHub Actions, pre-commit)

### What you are building

Every validated exploit from Phase 6 and every confirmed invariant violation needs to
become a finding in a structured report. Without this phase, the system produces JSON
that only an engineer running the pipeline can interpret. A report generator makes the
output accessible to protocol teams, DAOs, and auditors.

Severity scoring from Phase 6 maps directly to report sections. The report should
follow a standard audit report structure:

```
Executive Summary
  - Total findings: X critical, Y high, Z medium
  - Protocols analyzed: ...
  - Analysis depth: phases completed

Findings
  [CRITICAL-001] Oracle Manipulation in LendingPool.borrow()
    - Description
    - Proof of Concept (transaction sequence)
    - Impact
    - Recommended Fix
    - Historical Precedent

Appendix
  - Protocol Graph Summary
  - Invariants Checked
  - Simulation Results
```

### CI/CD Integration

Provide a GitHub Actions workflow and pre-commit hook that:
  - Runs Phase 1 + Phase 2 on every PR touching .sol files
  - Posts a summary comment to the PR with any new invariant violations
  - Blocks merge if critical findings are present (configurable)
  - Stores results in Phase 8 knowledge graph automatically

This is the developer-facing moat. Security research runs autonomously;
developers get findings in their existing workflow without running anything manually.

---

## PHASE 10: Real-Time On-Chain Monitor (New)

### Goal

Use the attack knowledge base defensively. Watch live transactions for
patterns matching known attack hypotheses before they succeed.

### What you are building

- mempool transaction monitor
- attack pattern matcher (against Phase 8 knowledge graph)
- alert system (Discord, Slack, PagerDuty)
- protocol health dashboard

### What you are building

The entire Phase 1-8 system is offensive: it finds vulnerabilities. Phase 10 inverts
this. The same protocol graphs, invariants, and attack patterns become a detection
system. A transaction in the mempool that matches a known exploit sequence triggers
an alert. The protocol team has the block time to react.

This is the same knowledge graph used two ways:
  - Offensive (Phases 1-8): find vulnerabilities before attackers do
  - Defensive (Phase 10): detect attacks in real time when they happen

### Integration

- Subscribe to mempool via WebSocket (Alchemy, Infura, or local node)
- For each pending transaction, check against Phase 8 attack pattern graph
- Alert if the transaction matches a known exploit sequence structure
- Include: matched pattern, confidence score, protocol affected, estimated impact

---

## Architecture: Complete Feedback Loop

```
                    ┌─────────────────┐
                    │  Phase 1        │
                    │  Protocol Graph │◄─── .sol files / GitHub / contract address
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Phase 2        │◄─── DeFiHackLabs / Rekt / Immunefi (RAG)
                    │  Invariants     │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Phase 3        │◄─── Phase 8 knowledge graph (pattern boost)
                    │  Swarm Agents   │     (5-7 specialized adversarial agents)
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Phase 4        │◄─── Live on-chain state (RPC)
                    │  Tx Sequences   │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Phase 5        │     Foundry/Anvil (Rust) + Echidna + Halmos
                    │  EVM Simulation │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Phase 6        │
                    │  Validation     │──── duplicate check ──► Phase 8
                    └────────┬────────┘
                             │
               ┌─────────────┼──────────────┐
               │             │              │
      ┌────────▼────┐ ┌──────▼──────┐ ┌────▼───────────┐
      │  Phase 7    │ │  Phase 8    │ │  Phase 9       │
      │  Swarm RL   │ │  GraphRAG   │ │  Audit Reports │
      │  Evolution  │ │  Knowledge  │ │  CI/CD         │
      └────────┬────┘ │  Graph      │ └────────────────┘
               │      └──────┬──────┘
               │             │              ┌────────────────┐
               └─────────────┴──────────────► Phase 10       │
                                            │  Live Monitor  │
                                            └────────────────┘
```

---

## Final Reality Check

If you build all phases:

You don't get a tool.

You get an Autonomous Security Research System that gets measurably smarter
with every protocol it analyzes.

**What actually matters most**

Not LLM quality.
Not fancy UI.

The real power is:

- simulation accuracy          ← Phase 5
- search efficiency            ← Phase 7 (swarm RL, not single PPO)
- validation strictness        ← Phase 6
- compounding memory           ← Phase 8 (GraphRAG, feedback loop)
- ground truth grounding       ← Phase 2 (RAG over real exploits)

That's where most people fail.

The swarm intelligence insight (from MiroFish's architecture) changes Phase 3 and
Phase 7 from "one model thinking hard" to "many specialized agents finding what
one model can't see." That is the architectural difference between a good tool and
a system that discovers vulnerabilities no human would think to look for.

---

## PHASE 11: LLM-Augmented Contest Mode (Audit-Contest Winning)

### Goal

Turn ZeroPath into a system that can take top-5 in audit contests
(Cantina, Code4rena, Sherlock, Immunefi). The deterministic 10-phase
pipeline is excellent SaaS infrastructure — but contest combat needs
LLM-class reasoning over Solidity semantics + spec/implementation gap
detection + verified PoCs + platform-specific submission shaping +
duplicate-likelihood ranking.

### What you are building

- LLM provider abstraction (Anthropic Claude Opus, OpenAI GPT/o1, local Llama — pluggable)
- LLM Reasoner agent with tool use (read_file, grep_codebase, lookup_past_finding)
- Audit corpus RAG layer (Phase 8 KG → context blocks for the reasoner)
- Spec miner (NatSpec + README + docs → claimed invariants)
- Spec/implementation mismatch detector
- Foundry PoC verifier (forge build + forge test, repair-on-failure loop)
- LLM contrarian pass (judge-style reject pass on every finding)
- Submission strategy (confidence gate + severity floor + duplicate-likelihood ranking)
- Platform formatters (Cantina, Code4rena, Sherlock, Immunefi schemas)
- Contest orchestrator (parallel per-file audit + cost-budget enforcement)
- Cost ledger with hard budget enforcement (--llm-budget-usd)

### Critical additions vs. the Phase 1-10 pipeline

**LLM Reasoner with tool use:**
The Phase 3 adversarial swarm is pattern-based deduction. ~50% of
contest-winning HIGH/CRITICAL findings require semantic reasoning over
protocol intent — "the code does X but the comment says Y, therefore Z
is broken." Without an LLM in the loop, ZeroPath misses those. The
Reasoner sits ALONGSIDE the swarm (not replacing it) and produces
findings the deterministic detectors can't.

**Spec/impl gap detection:**
The single highest-payoff bug class in audit contests is the gap between
NatSpec/README claims and actual code behaviour. The Spec Miner extracts
every "MUST", "SHALL", "always", "never" claim from NatSpec + README +
docs, then the Mismatch Detector flags any claim not enforced by a
Phase 2 invariant. These become first-class candidate findings.

**Verified PoCs — not template PoCs:**
Phase 9's report generator produces .t.sol files. Contest judges reject
findings whose PoC doesn't actually run. The Foundry PoC Verifier:
  - Compiles the generated test in a scratch or contest-supplied workspace
  - Runs `forge test --match-path` with the expected assertion
  - Captures compile + revert errors for the LLM to repair and retry
  - Downgrades confidence on findings whose PoC won't run

**Duplicate-likelihood scoring:**
Contests pay less for findings other auditors also submit. The strategy
module estimates per-finding duplicate likelihood (per-class baseline +
KG-weighted boost + novelty discount + spec-violation discount) and
submits low-dup findings first.

**Per-platform submission formatting:**
Cantina, Code4rena, Sherlock, Immunefi each have their own submission
shapes (JSON, Markdown with severity codes, impact × likelihood matrix,
etc.). One platform-agnostic Finding model, four adapters.

**Cost ledger:**
LLM calls add up fast on a 50-file contest. The ledger caps spend at
``--llm-budget-usd 200`` and short-circuits the audit loop when the
budget is hit, so a runaway prompt can't drain a credit card.

### Output (ContestReport)

```json
{
  "config": {"platform": "cantina", "repo_path": "./contracts", ...},
  "submissions": [
    {
      "rank": 1,
      "disposition": "submit_now",
      "finding": {
        "title": "Single-block oracle manipulation in LendingPool.borrow()",
        "severity": "critical",
        "attack_class": "oracle_manipulation",
        "contracts_involved": ["LendingPool"],
        "lines_of_code": ["src/LendingPool.sol#L42-L60"],
        "description": "...",
        "impact": "...",
        "attack_path": ["1. flash-loan WETH...", "2. swap to skew...", ...],
        "proof_of_concept_code": "// .t.sol that compiles + asserts profit",
        "proof_of_concept_run_log": "[PASS] test_oracleManipulation() ...",
        "recommendation": "Replace spot price with TWAP (≥30 min window)",
        "confidence": 0.85,
        "duplicate_likelihood": 0.32,
        "historical_precedents": [
          {"protocol": "Cream Finance", "loss_usd": 130000000, ...}
        ]
      },
      "rendered_payload": { ... platform-specific JSON ... }
    }
  ],
  "summary": {
    "files_scanned": 32, "raw_findings": 24,
    "actionable_findings": 11, "submitted_count": 8, "discarded_count": 3,
    "by_severity": {"critical": 2, "high": 5, "medium": 3, "low": 1},
    "llm_spent_usd": 47.23, "llm_calls": 89, "elapsed_seconds": 412.6
  }
}
```

### CLI surface

```bash
zeropath contest ./contracts \
    --platform cantina \
    --scope ./scope.txt \
    --llm-budget-usd 200 \
    --confidence-threshold 0.70 \
    --severity-floor medium \
    --invariants output/invariants.json \
    --kg-dir ./kg/ \
    -o output/cantina-submissions.json
```

### Pipeline

```
spec mine  ───►  parallel per-file LLM audit (Claude Opus + KG-RAG + tools)
                          │
                          ▼
                Foundry compile + test the PoC
                          │
                          ▼
              LLM contrarian — would a judge reject this?
                          │
                          ▼
              Strategy: confidence + severity gate, dup-likelihood rank
                          │
                          ▼
           Platform formatter (Cantina / C4R / Sherlock / Immunefi)
                          │
                          ▼
                 submissions.json ready to submit
```

### Graceful degradation

Every external dependency is optional:

  - No `ANTHROPIC_API_KEY` / no `openai` pkg → spec miner runs, mismatch detector flags gaps, formatters work; LLM audit skipped
  - No `forge` on PATH → pipeline runs; PoCs template-only, not verified
  - No Phase 8 KG dir → no historical-precedent RAG context
  - No Phase 2 invariants → LLM audit runs with less context

---

## PHASE 12: MCP Server (IDE-Side Distribution)

### Goal

Let any IDE-side AI agent (Claude Code, Cursor, Cline, Continue.dev,
Claude Desktop, Zed, Windsurf) drive ZeroPath without the user having
to set up an API key. The IDE's existing LLM subscription does the
reasoning; ZeroPath exposes its capabilities as Model Context Protocol
tools / resources / prompts.

### What you are building

- Pure-stdlib JSON-RPC 2.0 implementation over newline-delimited stdio
- MCPServer dispatcher (initialize, tools/list+call, resources/list+read+templates, prompts/list+get)
- 12 tools wrapping Phase 1-10 + contest mode + KG queries
- 6 resources + 2 URI templates exposing graph / invariants / KG / contest reports
- 4 pre-built prompts (contest_audit, spec_extract, contrarian_review, kg_ground_attack_class)
- IDE auto-installer for 5 clients (Claude Desktop, Claude Code, Cursor, Cline, Continue) with idempotent merge + auto-backup
- `zeropath mcp` CLI group: install / uninstall / serve / tools

### Critical additions vs. running CLI directly

**Zero-credential workflow:**
User runs `zeropath mcp install --client claude-code`, restarts IDE,
and the agent now has 12 ZeroPath tools available. No API key setup,
no separate subscription, no env vars. The IDE's existing LLM
(Claude Opus / GPT-5 / whichever the user pays for) handles reasoning.

**Conversational steering:**
With the MCP server, the user can say "audit this contract but focus on
the lending pool — skip the test files" mid-conversation. Direct-API
calls don't support that; MCP does.

**Statefulness:**
The MCP server holds the loaded protocol graph, invariant report, and
last contest report in memory across tool calls. Skill-based
distribution reloads from disk every invocation.

**Typed tool schemas:**
Every tool exposes a JSON Schema so the IDE agent always knows the
exact signature. No prose interpretation required.

### Pure-stdlib protocol implementation

To keep install footprint minimal and survive any IDE's invocation
pattern, the MCP protocol is implemented from scratch in pure Python.
No `mcp` SDK dependency, no native extensions. ~250 LOC for the
protocol + server + transport.

### Tools exposed

  - `analyze_protocol`  — Phase 1 graph builder
  - `infer_invariants`  — Phase 2 detector pipeline
  - `mine_spec_claims`  — Spec miner
  - `verify_foundry_poc`  — Compile + run a .t.sol PoC
  - `query_kg_similar_exploits`  — Phase 8 similarity
  - `query_kg_historical_grounding`  — KG → confidence boost + matched incidents
  - `ingest_threat_intel`  — Manual KG ingest
  - `ingest_defihacklabs_live`  — Live KG fetch from GitHub
  - `kg_summary`  — KG stats
  - `run_contest_pipeline`  — Deterministic contest pipeline (LLM disabled — IDE supplies reasoning)
  - `format_finding_for_platform`  — Cantina/C4R/Sherlock/Immunefi adapter
  - `estimate_duplicate_likelihood`  — Submission strategy scoring

### Resources exposed

  - `zeropath://kg/summary` — top-level KG stats
  - `zeropath://kg/findings` — validated-exploits index
  - `zeropath://kg/incidents` — historical-incidents index
  - `zeropath://kg/findings/{id}` — one validated exploit by id (template)
  - `zeropath://kg/incidents/{id}` — one historical incident (template)
  - `zeropath://contest/last-report` — most recent ContestReport
  - `zeropath://graph/latest` — most recent ProtocolGraph
  - `zeropath://invariants/latest` — most recent InvariantReport

### Prompts exposed

  - `contest_audit` — runs the full contest workflow
  - `spec_extract` — runs spec mining + manual mismatch check
  - `contrarian_review` — judge-style rejection pass on a finding
  - `kg_ground_attack_class` — surface historical precedents for an attack class

### Distribution architecture

```
                ┌──────────────────────────────────────────────────┐
                │ ZeroPath core (Phase 1-10 + contest + KG)        │
                └──────────────────┬──────────────────────────┬───┘
                                   │                          │
                  ┌────────────────┴───────┐   ┌──────────────┴──────┐
                  │ MCP server (stdio)     │   │ Direct CLI / API    │
                  │ (Phase 12)             │   │ + contest mode      │
                  └────────────────┬───────┘   └─────────────────────┘
                                   │
                  ┌────────────────┴───────────────────────────┐
                  ▼                                              ▼
            IDE-side agents                          CI/CD pipelines
            (Claude Code, Cursor, Cline,           GitHub Actions
             Continue, Claude Desktop,              Pre-commit
             Zed, Windsurf, ChatGPT Desktop)        Headless batch
```

---

## PHASE 13: Contest Corpus Ingestion (Next)

### Goal

Seed the Phase 8 knowledge graph with ~35,000+ historical contest
findings so the LLM Reasoner's RAG context (Phase 11) and the
duplicate-likelihood scoring become real signal instead of class-baseline
heuristics.

### What you are building

- Code4rena report scraper (github.com/code4rena/reports) — ~3,000 findings
- Sherlock report scraper (github.com/sherlock-protocol/reports) — ~2,000 findings
- Cantina disclosure scraper (cantina.xyz/competitions) — ~1,500 findings
- Solodit ingester (solodit.cyfrin.io) — ~30,000 curated findings
- Spearbit report scraper (spearbit.com/reports) — ~500 findings
- Unified `zeropath kg ingest --source X` CLI command
- `zeropath kg seed-all` one-shot bootstrap
- Local cache so re-running doesn't re-fetch
- Idempotent KG inserts (fingerprint-based dedup)

### Critical design notes

**HTTP-only, no API keys:**
Code4rena + Sherlock are GitHub repos — `git clone` or raw-file fetch
works without auth. Cantina disclosures are public HTML pages. Solodit
has a public search interface. The corpus loader needs zero
credentials to bootstrap.

**Reuse `ExternalIncidentRecord`:**
Contest findings fit the same schema as DeFiHackLabs / Rekt entries —
just with `source ∈ {code4rena, sherlock, cantina, solodit, spearbit}`,
`loss_usd=0` (no actual loss for audit findings), and `tags` carrying
severity codes ("severity:H", "contest:cantina-aave-v3").

**Cache locally:**
~/.zeropath/cache/ holds the cloned repos + parsed HTML so re-running
costs near-zero network. Each scraper checks cache mtime against
"last ingested at" to skip unchanged files.

**Idempotent KG inserts:**
Fingerprint each finding on (source, contest_id, finding_title) so
re-running `seed-all` updates rather than duplicates. Phase 6
DuplicateDetector's fingerprint protocol already supports this.

### CLI surface

```bash
zeropath kg ingest --source code4rena --kg-dir ./kg
zeropath kg ingest --source sherlock --kg-dir ./kg
zeropath kg ingest --source cantina --kg-dir ./kg
zeropath kg ingest --source solodit --kg-dir ./kg --limit 5000

# One-shot bootstrap of every source:
zeropath kg seed-all --kg-dir ./kg
```

### Expected outcome

After `seed-all` completes:

  - LLM Reasoner's `lookup_past_finding` tool returns 5-10 structurally similar past contest findings per file
  - `estimate_duplicate_likelihood` becomes distribution-driven instead of baseline-heuristic
  - `query_kg_historical_grounding` surfaces relevant incidents for every common attack class
  - Phase 3 swarm gets the historical-precedent boost the spec already calls for
  - The KG becomes the moat — every contest run gets smarter than the last

This is the highest-leverage move for contest competitiveness because the
LLM Reasoner is only as good as the context it's grounded in.

---

## PHASE 14: EVMbench Harness (Measurement)

### Goal

Measure ZeroPath's contest performance against the OpenAI + Paradigm
EVMbench benchmark (Feb 2026 — 120 curated vulnerabilities from 40
professional audits). Without a public scoreboard, "is ZeroPath
beating V12?" is unanswerable.

### What you are building

- EVMbench downloader / cloner
- Per-item runner (runs full contest mode against one bench fixture)
- Recall / precision / mean-time-to-find metrics
- A/B harness for prompt versions (`PROMPT_VERSION` in llm/prompts.py)
- Baseline comparison report (ZeroPath vs ZeroPath+ContestMode vs
  ZeroPath+Phase13-KG)

### Target outcome

ZeroPath's published EVMbench score >= V12's published score on the
same benchmark version. Optimise prompt + thresholds until this holds.
This is the bar for "we are competitive in audit contests."
