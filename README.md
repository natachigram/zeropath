# ZeroPath

Autonomous smart contract security research for DeFi protocols.

ZeroPath builds a protocol-level model of a smart contract system, infers the
economic invariants that should hold, generates adversarial attack hypotheses,
and turns high-signal hypotheses into executable transaction sequences,
validated findings, audit-contest submissions, and agent-accessible security
research context.

The project is designed around one standard:

> A finding is only useful if it can survive adversarial validation.

ZeroPath is not a pattern scanner. It is a research pipeline for moving from
source code to protocol graph, from graph to invariants, from invariants to
attack hypotheses, and from hypotheses to concrete exploit candidates.

---

## Why ZeroPath Exists

Most smart contract analysis tools are excellent at surfacing local risks:
dangerous calls, missing checks, suspicious state writes, or known vulnerable
patterns. Real DeFi exploits are usually less local. They emerge from system
state, accounting assumptions, oracle dependencies, cross-contract ordering,
and the gap between what a protocol assumes and what an attacker can compose.

ZeroPath is built for that gap.

It treats a protocol as a financial system:

- What value enters the system?
- Where can it move?
- Which state relationships must remain true?
- Which external dependencies can be bent by an attacker?
- Can a sequence of transactions produce measurable profit under realistic
  constraints?

The goal is not to report more issues. The goal is to report fewer, better,
more defensible issues.

---

## Current Status

ZeroPath is under active development. The public CLI exposes the core
Phase 1-4 research workflow plus contest mode, MCP server integration, and
knowledge-graph corpus ingestion. Phases 5-10 are implemented as source/API
modules with tests and are being folded into more end-to-end command surfaces.

| Area | Status | Notes |
| --- | --- | --- |
| Phase 1: protocol ingestion and graph builder | Implemented | Solidity/Vyper parsing, storage layout, asset flows, proxy detection, GitHub/on-chain inputs, Neo4j export |
| Phase 2: invariant inference | Implemented | DeFi pattern detection, oracle mapping, invariant detectors, historical-precedent metadata, formal spec fields |
| Phase 3: adversarial swarm | Implemented | Specialized agents, debate rounds, consensus ranking, hypothesis rejection |
| Phase 4: transaction sequencing | Implemented | Attack-class builders, ABI encoding, gas estimates, mutation support, Foundry/Hardhat PoC generation |
| Phase 5: simulation | In source/API | Anvil execution, state tracking, revert analysis, Echidna/Medusa/Halmos adapters |
| Phase 6: validation | In source/API | Profit, permission, realism, severity, duplicate, and contrarian validators |
| Phase 7: exploit evolution | In source/API | Population-based RL, curriculum scheduling, HITL signals, checkpointing |
| Phase 8: knowledge graph | Implemented | Exploit records, incident records, inference records, in-memory and Neo4j stores |
| Phase 9: audit reporting | In source/API | Markdown, HTML, PDF, JSON, SARIF, GitHub, GitLab, and JUnit report writers |
| Phase 10: real-time monitor | In source/API | Transaction subscribers, signature matching, alert routing, incident metadata |
| Phase 11: contest mode | Implemented | LLM reasoner, spec miner, Foundry PoC verifier, duplicate scoring, platform formatters, budget ledger |
| Phase 12: MCP server | Implemented | stdio JSON-RPC server, tools/resources/prompts, IDE config installers |
| Phase 13: contest corpus ingestion | Implemented | Code4rena, Sherlock, Cantina metadata, Solodit, and Spearbit ingestion into the KG |
| Phase 14: EVMbench harness | Specified | Benchmark runner and prompt A/B harness are planned in `phases.md` |

---

## Architecture

```text
contracts / repo / address
        |
        v
Protocol Ingestion
        |
        v
Protocol Graph
        |
        v
Invariant Inference
        |
        v
Adversarial Swarm
        |
        v
Transaction Sequences
        |
        v
Simulation + Validation
        |
        v
Audit Reports + Knowledge Graph + Learning Loop
        |
        v
Contest Mode / MCP / Monitoring
```

The architecture is intentionally modular. Each stage produces structured data
that can be inspected, tested, persisted, or replaced by a stronger component.

### Protocol Graph

ZeroPath parses contracts into a typed graph containing:

- contracts, inheritance, language, compiler metadata
- functions, selectors, modifiers, visibility, mutability, and access controls
- state variables, storage slots, reads, and writes
- internal, external, low-level, delegatecall, staticcall, and library calls
- events and external dependencies
- asset flow paths
- proxy relationships and upgradeability indicators
- version-diff metadata for upgrade review

### Invariant Engine

The invariant engine looks for properties that should remain true across the
whole system, including:

- value conservation
- balance consistency
- collateralization relationships
- share accounting
- oracle manipulation resistance
- reentrancy boundaries
- flash-loan safety
- governance safety
- cross-protocol composability assumptions

Invariants are scored, sorted by severity and confidence, and enriched with
machine-readable fields for downstream simulation and formal checks.

### Adversarial Swarm

ZeroPath uses specialized attack agents instead of a single generic reasoning
pass. The current swarm includes agents for:

- oracle and price manipulation
- reentrancy
- access control
- flash loans
- composability
- governance
- integer math

Agents generate hypotheses independently, critique each other through debate
rounds, and pass their results through a consensus aggregator that deduplicates,
ranks, and rejects weak candidates.

### Sequence Generation

The sequencer converts attack hypotheses into concrete transaction plans:

- selects a builder based on attack class
- binds calldata through an ABI encoder
- estimates gas and prunes unprofitable candidates where possible
- expands candidates through mutation
- emits Foundry and Hardhat proof-of-concept scaffolds

### Contest Mode

Contest mode layers LLM-assisted audit reasoning on top of the deterministic
pipeline. It mines NatSpec, README, and docs claims, audits in-scope Solidity
files with optional KG-backed RAG context, verifies generated Foundry PoCs when
`forge` is available, runs a contrarian review pass, ranks findings by severity,
confidence, and duplicate likelihood, then renders platform-specific payloads.

Supported platforms:

- Cantina
- Code4rena
- Sherlock
- Immunefi
- generic JSON

Every external dependency degrades gracefully. Without an LLM key, spec mining,
formatting, and deterministic stages still run. Without Foundry, PoCs remain
template-only. Without a KG snapshot, historical context and duplicate scoring
fall back to local heuristics.

### Model Context Protocol

The MCP server lets IDE-side agents call ZeroPath over stdio without adding a
separate hosted service. It exposes tools for graph analysis, invariant
inference, spec mining, Foundry PoC verification, KG queries, contest-pipeline
helpers, platform formatting, and duplicate-likelihood scoring.

Supported installer targets:

- Claude Desktop
- Claude Code
- Cursor
- Cline
- Continue

### Contest Corpus KG

Contest corpus ingestion seeds the Phase 8 knowledge graph with historical audit
findings and review metadata. The KG can then ground LLM prompts, surface
similar precedent, and make duplicate-likelihood scoring less heuristic.

Supported sources:

- Code4rena reports
- Sherlock judging reports
- Cantina portfolio metadata
- Solodit findings, via API key or local dump
- Spearbit portfolio metadata

---

## Installation

ZeroPath requires Python 3.11 or newer.

```bash
git clone <repo-url>
cd zeropath
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Optional external tools:

- Slither and a working Solidity compiler toolchain for source analysis
- Neo4j for graph persistence and Cypher exploration
- Foundry/Anvil for realistic EVM simulation
- Echidna, Medusa, and Halmos for fuzzing and symbolic checks

Start Neo4j locally:

```bash
make neo4j
```

---

## Quick Start

Analyze the included example contract:

```bash
zeropath analyze example_contracts/SimpleToken.sol -o output/graph.json
```

Run invariant inference:

```bash
zeropath infer output/graph.json \
  --protocol-name SimpleToken \
  -o output/invariants.json
```

Generate adversarial hypotheses:

```bash
zeropath attack output/invariants.json output/graph.json \
  -o output/attack_report.json
```

Generate transaction sequences and PoC scaffolds:

```bash
zeropath sequence output/attack_report.json output/graph.json \
  -o output/sequences
```

Run an audit-contest pipeline:

```bash
zeropath contest ./contracts \
  --platform cantina \
  --scope ./scope.txt \
  --llm-budget-usd 200 \
  --confidence-threshold 0.70 \
  --severity-floor medium \
  --invariants output/invariants.json \
  --kg-dir ./kg \
  -o output/cantina-submissions.json
```

Install the MCP server for an IDE-side agent:

```bash
zeropath mcp install --client claude-code --kg-dir ./kg
zeropath mcp tools
```

Seed the knowledge graph with contest findings:

```bash
zeropath kg ingest --source code4rena --kg-dir ./kg --max 1000
zeropath kg seed-all --kg-dir ./kg --max-per-source 1000
zeropath kg summary --kg-dir ./kg
```

Or run the demo target:

```bash
make demo
```

---

## CLI

```text
zeropath analyze       Build a protocol graph from source, GitHub, or an address
zeropath infer         Infer protocol invariants from a saved graph
zeropath attack        Run the adversarial swarm on invariant output
zeropath sequence      Generate transaction sequences and PoC files
zeropath diff          Compare two protocol versions
zeropath import-graph  Import a graph JSON file into Neo4j
zeropath query         Open an interactive Neo4j query shell
zeropath contest       Run the contest-mode pipeline and emit submissions JSON
zeropath mcp           Install, serve, uninstall, or inspect the MCP server
zeropath kg            Ingest contest corpora and inspect KG summaries
```

Supported analysis inputs:

- local Solidity or Vyper file
- local directory of contracts
- GitHub URL
- GitHub `owner/repo` shorthand
- Ethereum contract address, with verified-source lookup where available

Example:

```bash
zeropath analyze https://github.com/owner/repo/tree/main/contracts \
  --workers 8 \
  --store-graph \
  --output output/graph.json
```

Version-diff review:

```bash
zeropath diff ./protocol-v1 ./protocol-v2 -o output/diff.json
```

Contest mode:

```bash
zeropath contest ./contracts \
  --platform code4rena \
  --contest-name "Example Contest" \
  --scope ./scope.txt \
  --kg-dir ./kg \
  -o output/submissions.json
```

MCP server commands:

```bash
zeropath mcp install --client all --kg-dir ./kg
zeropath mcp serve --kg-dir ./kg
zeropath mcp tools
zeropath mcp uninstall --client cursor
```

Knowledge graph corpus commands:

```bash
zeropath kg ingest --source sherlock --kg-dir ./kg
zeropath kg ingest --source solodit --kg-dir ./kg --solodit-dump ./solodit.json
zeropath kg seed-all --kg-dir ./kg --skip cantina
zeropath kg summary --kg-dir ./kg
```

---

## Python API

```python
from pathlib import Path

from zeropath import ProtocolGraphBuilder
from zeropath.adversarial import SwarmOrchestrator
from zeropath.contest import ContestConfig, ContestOrchestrator, ContestPlatform
from zeropath.invariants import InvariantInferenceEngine
from zeropath.sequencer import SequenceOrchestrator, TestFramework

builder = ProtocolGraphBuilder(max_workers=4)
graph = builder.build_from_directory(Path("contracts"))

invariants = InvariantInferenceEngine().analyse(
    graph,
    protocol_name="MyProtocol",
)

swarm_report = SwarmOrchestrator(
    max_workers=4,
    debate_rounds=2,
).run(invariants, graph)

sequence_report = SequenceOrchestrator(
    frameworks=TestFramework.BOTH,
    min_confidence=0.40,
).run(swarm_report, graph)

contest_report = ContestOrchestrator(
    ContestConfig(
        platform=ContestPlatform.CANTINA,
        repo_path="./contracts",
        llm_budget_usd=200.0,
        submit_confidence_threshold=0.70,
    )
).run()
```

---

## Configuration

Core configuration is loaded with Pydantic settings. ZeroPath-owned environment
variables use the `ZEROPATH_` prefix; vendor integrations use their standard
provider variable names.

Common settings:

```bash
export ZEROPATH_NEO4J_URI=bolt://localhost:7687
export ZEROPATH_NEO4J_USERNAME=neo4j
export ZEROPATH_NEO4J_PASSWORD=password
export ZEROPATH_ETHERSCAN_API_KEY=<api-key>
export ZEROPATH_RPC_URL=<json-rpc-url>
export ZEROPATH_DEFAULT_CHAIN=mainnet
export ZEROPATH_MAX_WORKERS=8
export ZEROPATH_LOG_LEVEL=INFO
```

For private GitHub repositories:

```bash
export ZEROPATH_GITHUB_TOKEN=<token>
```

For direct LLM contest runs:

```bash
export ANTHROPIC_API_KEY=<api-key>
export OPENAI_API_KEY=<api-key>
export ZEROPATH_LLM_LOCAL_BASE_URL=http://localhost:11434
```

Only the provider you want to use needs to be configured, and direct LLM
support depends on the corresponding vendor SDK being installed in the active
environment.

For Solodit corpus ingestion:

```bash
export SOLODIT_API_KEY=<api-key>
# or
export CYFRIN_API_KEY=<api-key>
```

---

## Repository Layout

```text
src/zeropath/
  parser.py                 Source parsing and Slither integration
  graph_builder.py          Protocol graph orchestration
  graph_db.py               Neo4j persistence and query helpers
  storage_analyzer.py       Storage-slot layout analysis
  asset_flow.py             ETH/token flow extraction
  proxy_detector.py         Proxy and upgradeability detection
  onchain_fetcher.py        Verified-source and bytecode fetching
  bytecode_decompiler.py    Heimdall-compatible bytecode fallback
  invariants/               Phase 2 invariant inference engine
  adversarial/              Phase 3 attack-agent swarm
  sequencer/                Phase 4 transaction sequencing and PoC generation
  simulator/                Phase 5 execution, fuzzing, and symbolic checks
  validation/               Phase 6 false-positive rejection pipeline
  rl/                       Phase 7 swarm RL and curriculum training
  knowledge/                Phase 8 exploit knowledge graph
  reporting/                Phase 9 audit report generation and CI formats
  monitor/                  Phase 10 transaction monitoring and alerts
  contest/                  Phase 11 contest orchestration and formatters
  llm/                      LLM providers, prompts, audit reasoner, KG RAG
  mcp_server/               Phase 12 stdio MCP server and IDE installers
tests/                      Unit and integration tests by phase
example_contracts/          Small Solidity fixtures for local runs
phases.md                   Full research and implementation specification
```

---

## Development

```bash
make install        # editable install with dev dependencies
make test           # run tests
make coverage       # generate html coverage report
make format         # black + isort
make ruff           # lint
make type-check     # mypy
```

The test suite is organized by subsystem and phase:

- parser, graph builder, storage, proxy, on-chain fetching, bytecode fallback
- invariant detectors and formal spec generation
- adversarial agents, debate, consensus, and full Phase 3 pipeline
- transaction sequencing, ABI encoding, gas estimation, mutation, and codegen
- simulator, validation, RL, and knowledge graph modules
- reporting, monitoring, contest mode, MCP server, and contest corpus ingestion

---

## Research Principles

ZeroPath is built around a few hard constraints:

- system-level reasoning over isolated function analysis
- economic exploitability over theoretical reachability
- explicit false-positive rejection over optimistic reporting
- modular stages over opaque end-to-end magic
- structured outputs over prose-only findings
- historical exploit grounding over abstract taxonomy
- reproducible PoC paths over vague attack narratives

The intended user is a security researcher or senior protocol engineer who wants
an assistant that can build and challenge exploit hypotheses, not merely list
warnings.

---

## Safety

ZeroPath is intended for authorized security research, audit preparation,
defensive protocol analysis, and education.

Do not use it against systems you do not own or have explicit permission to
test. You are responsible for complying with applicable laws, disclosure
processes, and program rules.

---

## License

No license file is currently included in this repository. Add one before public
distribution or third-party reuse.
