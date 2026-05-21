# ZeroPath

Autonomous smart contract security research for DeFi protocols.

ZeroPath builds a protocol-level model of a smart contract system, infers the
economic invariants that should hold, generates adversarial attack hypotheses,
and turns high-signal hypotheses into executable transaction sequences.

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

ZeroPath is under active development. The public CLI currently exposes the core
pipeline through Phase 4, with later phases present as source modules and tests
that are being integrated into the end-to-end workflow.

| Area | Status | Notes |
| --- | --- | --- |
| Phase 1: protocol ingestion and graph builder | Implemented | Solidity/Vyper parsing, storage layout, asset flows, proxy detection, GitHub/on-chain inputs, Neo4j export |
| Phase 2: invariant inference | Implemented | DeFi pattern detection, oracle mapping, invariant detectors, historical-precedent metadata, formal spec fields |
| Phase 3: adversarial swarm | Implemented | Specialized agents, debate rounds, consensus ranking, hypothesis rejection |
| Phase 4: transaction sequencing | Implemented | Attack-class builders, ABI encoding, gas estimates, mutation support, Foundry/Hardhat PoC generation |
| Phase 5: simulation | In source | Anvil execution, state tracking, revert analysis, Echidna/Medusa/Halmos adapters |
| Phase 6: validation | In source | Profit, permission, realism, severity, duplicate, and contrarian validators |
| Phase 7: exploit evolution | In source | Population-based RL, curriculum scheduling, HITL signals, checkpointing |
| Phase 8: knowledge graph | In source | Exploit records, incident records, inference records, in-memory and Neo4j stores |

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
Knowledge Graph + Learning Loop
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

---

## Python API

```python
from pathlib import Path

from zeropath import ProtocolGraphBuilder
from zeropath.adversarial import SwarmOrchestrator
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
```

---

## Configuration

Configuration is loaded with Pydantic settings. Environment variables use the
`ZEROPATH_` prefix.

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
