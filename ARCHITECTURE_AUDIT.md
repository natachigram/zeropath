# ZeroPath Architecture Audit

Date: 2026-06-08

Scope: `src/zeropath` source modules. Generated `__pycache__` directories were
observed locally, but they are not architecture modules and are not tracked by
git.

Architecture standard for this audit: ZeroPath is evidence-first, CLI-first,
MCP-compatible, memory-backed, judge-gated, and adapter-based. Code that still
assumes autonomous audit swarms, RL exploit evolution, monitoring, or old graph
pipelines is classified as experimental or legacy unless it is directly used by
the evidence workflow.

## Summary

The new architecture lives primarily in:

- `core`
- `adapters/evm`
- `cli/commands`
- `mcp`
- `templates`

The old architecture still lives in:

- root graph helpers such as `graph_builder.py`, `models.py`, `parser.py`
- `adversarial`
- `invariants`
- `sequencer`
- `simulator`
- `contest`
- `knowledge`
- `llm`
- `monitor`
- `reporting`
- `rl`
- `validation`
- `mcp_server`

These old modules are not deleted in this milestone because they still have
tests and compatibility command surfaces. They should be treated as legacy or
experimental unless explicitly wired through the evidence-first workflow.

## Module Classification

| Module | Classification | What it currently does | Belongs in new architecture? | Used by tests? | Imported by CLI or MCP? | Action |
|---|---|---|---|---|---|---|
| `src/zeropath` root helpers | legacy | Holds older graph/parser/storage/on-chain helpers (`graph_builder.py`, `models.py`, `asset_flow.py`, `proxy_detector.py`, etc.). | Partially. Config, exceptions, and logging stay; old graph helpers are legacy. | Yes, through older phase tests. | Imported by legacy `analyze`, `diff`, `import-graph`, `query`. | Deprecate old graph helper usage; keep shared config/logging. |
| `adapters` | adapter | Defines adapter interface and ecosystem-specific implementations. | Yes. This is a core architectural boundary. | Yes. | Imported by `ingest`, `prove`, MCP evidence tools. | Keep. |
| `adapters/evm` | adapter/proof/backend | Detects EVM projects, lightly parses Solidity, suggests EVM invariants, renders Foundry PoC skeletons, and runs scoped Forge tests. | Yes. Stable first adapter, though parsing and PoC generation remain heuristic. | Yes. | Imported by CLI `ingest`/`prove` and MCP evidence tools. | Keep; improve parsing and proof generation next. |
| `adapters/move` | adapter | Placeholder adapter. | Belongs as planned adapter only. Not stable. | Minimal/import only if any. | Not imported by stable CLI/MCP. | Keep as placeholder; mark planned. |
| `adapters/solana` | adapter | Placeholder adapter. | Belongs as planned adapter only. Not stable. | Minimal/import only if any. | Not imported by stable CLI/MCP. | Keep as placeholder; mark planned. |
| `adapters/cosmwasm` | adapter | Placeholder adapter. | Belongs as planned adapter only. Not stable. | Minimal/import only if any. | Not imported by stable CLI/MCP. | Keep as placeholder; mark planned. |
| `adapters/cairo` | adapter | Placeholder adapter. | Belongs as planned adapter only. Not stable. | Minimal/import only if any. | Not imported by stable CLI/MCP. | Keep as placeholder; mark planned. |
| `adversarial` | experimental/legacy | Old Phase 3 swarm agents, debate, consensus, and hypothesis models. | No for stable workflow; yes only as research playground. | Yes, heavily in phase tests. | Imported by legacy `attack`, legacy `sequence`, legacy MCP tools. | Deprecate as stable surface; keep experimental. |
| `cli` | CLI/interface | Exposes the root Click CLI and command modules. Current stable commands are `init`, `ingest`, `status`, `understand`, `hunt`, `candidates`, `prove`, `judge`, `report`, `memory`, and `mcp`. | Yes. CLI-first is central. | Yes. | It is the CLI. | Keep; legacy commands now warn. |
| `cli/commands` | CLI/interface | Houses evidence-first command implementations. | Yes. | Yes. | Imported by `cli/main.py`. | Keep. |
| `contest` | experimental | Runs an older contest workflow with platform formatting, LLM/spec-mining, KG, and validation. | Not stable. Could become an orchestrated wrapper only after evidence gating is stronger. | Yes. | Imported by experimental `contest` and legacy MCP tools. | Keep experimental; do not market as stable. |
| `core` | core | Project config, storage, schemas, protocol intent, invariant catalog, candidate lifecycle, evidence scoring, state planning, judge, memory, and report export. | Yes. This is the canonical engine. | Yes. | Imported by stable CLI and canonical MCP. | Keep. |
| `invariants` | legacy/experimental | Old Phase 2 invariant inference engine, detectors, spec miner, RAG helpers, and invariant models. | Partially. Invariant ideas belong, but stable invariant suggestions now live in `core/invariants.py` and `adapters/evm/invariants.py`. | Yes. | Imported by legacy `infer`, experimental `contest`, and legacy MCP. | Deprecate old CLI path; merge useful detectors into adapter/core over time. |
| `knowledge` | memory/knowledge experimental | Contest corpus ingestion, KG stores, similarity, threat intel, temporal analysis, feedback loop. | Partially. Memory belongs, but this KG/corpus layer is older and not the stable memory router. | Yes. | Imported by legacy `kg`, experimental `contest`, and legacy MCP. | Keep experimental; do not claim real Solodit ingestion as stable. |
| `llm` | experimental | LLM provider abstractions, prompts, reasoner, and audit corpus helpers for older contest mode. | Not stable core. LLM use should stay outside the evidence gate. | Yes. | Imported by experimental `contest`. | Keep experimental. |
| `mcp` | CLI/interface | Canonical evidence-first MCP wrapper around core/adapters. Exposes ZeroPath tools and permissions, with write tools requiring explicit write mode. | Yes. Canonical MCP implementation. | Yes. | Imported by `zeropath mcp` command and tests. | Keep as canonical. |
| `mcp_server` | legacy/duplicate | Older combined MCP package with JSON-RPC transport, installers, resources, prompts, and old graph/KG/contest tools. Also provides shared MCP primitives used by canonical `mcp`. | Partially. Transport and installer belong; legacy tools/resources/prompts do not belong in canonical evidence-first MCP. | Yes. | Installer is imported by CLI `mcp install/uninstall`; legacy builder is still tested. | Deprecate as direct server surface; later split shared transport/installer into a neutral package and retire legacy tools. |
| `monitor` | experimental/legacy | Monitoring, mempool matching, alerting, signatures, and dashboard-style models. | No for current stable workflow. | Yes, phase tests. | Not imported by stable CLI/MCP. | Keep experimental or move under `experimental/monitor`. |
| `reporting` | reporting legacy | Older audit report models, ranking, remediation, Markdown/HTML/PDF/CI writers. | Partially. Reporting belongs, but stable judge-gated export is now `core/reports.py`. | Yes or indirect older tests. | Imported by older workflows, not stable CLI report command. | Deprecate as stable path; merge useful formatters into `core/reports.py` only when evidence-gated. |
| `rl` | experimental/legacy | Reinforcement-learning exploit evolution environment, agents, rewards, checkpoints, curricula, HITL loop. | No for current architecture. | Phase tests only if present. | Not imported by stable CLI/MCP. | Deprecate; move to experimental before future work. |
| `sequencer` | proof/backend experimental | Old transaction sequence generation, ABI encoding, mutation, gas estimation, code generation, on-chain state helpers. | Partially. State planning/proof belongs, but stable path is `core/state_plan.py` plus adapter proof backends. | Yes. | Imported by legacy `sequence`, experimental/legacy tests. | Keep experimental; merge proven pieces into adapter proof backends. |
| `sequencer/builders` | proof/backend experimental | Builder strategies for composability and transaction paths. | Not stable. | Yes. | Imported by sequencer tests. | Keep experimental. |
| `sequencer/codegen` | proof/backend experimental | Old Foundry/Hardhat test code generation. | Not stable. | Yes. | Imported by old sequencer. | Merge useful codegen into `adapters/evm/poc_templates.py` later. |
| `simulator` | proof/backend experimental | Foundry verifier, Anvil process helpers, fuzzer, executor, Halmos hooks, state tracker, revert analyzer. | Partially. Proof backends belong, but current stable proof path is adapter-scoped and conservative. | Yes. | Imported by experimental `contest` and legacy MCP. | Keep experimental; promote only pieces that produce strict evidence. |
| `templates` | reporting | Agent, PoC, and report templates included as package data. | Yes, if used by evidence-gated workflows. | Indirect. | Used by packaging and template consumers. | Keep. |
| `templates/agent` | CLI/interface | Agent-facing prompt/template assets. | Partially. Useful for MCP/IDE flows if honest. | Indirect. | Package data only. | Keep; review wording for overclaims. |
| `templates/pocs` | proof/backend | PoC template assets. | Yes, but skeletons are experimental until they produce concrete tests. | Indirect. | Package data and adapter paths. | Keep; improve specificity. |
| `templates/reports` | reporting | Report template assets. | Yes when judge-gated. | Indirect. | Package data. | Keep. |
| `validation` | experimental/legacy | Contrarian review, duplicate detection, severity scoring, validators. | Partially. Validation belongs, but stable gate is currently `core/judge.py`. | Yes. | Imported by experimental contest/knowledge tests, not stable CLI. | Keep experimental; merge deterministic checks into judge when evidence-backed. |

## CLI Command Decision

Recommended stable workflow:

```bash
zeropath init
zeropath ingest
zeropath understand
zeropath hunt
zeropath prove
zeropath judge
zeropath report
```

Old command decisions:

| Command | Decision |
|---|---|
| `analyze` | Keep as legacy alias/surface for old graph generation; warns to use `ingest` then `understand`. |
| `infer` | Keep as legacy invariant inference; warns to use `understand`. |
| `attack` | Keep as legacy swarm path; warns to use `hunt --mode critical`. |
| `sequence` | Keep as legacy sequence generator; warns to use `candidates plan` then `prove`. |
| `query` | Keep as legacy Neo4j shell; warns to use `memory search`. |
| `kg` | Keep as legacy KG corpus store; warns to use `memory`. |
| `contest` | Keep as experimental workflow; warns before running. |
| `diff` | Keep as legacy version-diff utility; warns that evidence-first review is preferred. |
| `import-graph` | Keep as legacy Neo4j import; warns to use `ingest`. |

## MCP Decision

There was functional duplication between:

- `src/zeropath/mcp`
- `src/zeropath/mcp_server`

Decision:

- `src/zeropath/mcp` is canonical for evidence-first MCP tools.
- `src/zeropath/mcp_server` remains only as a legacy combined server plus shared
  JSON-RPC transport and installer utilities.
- The CLI `zeropath mcp` and `zeropath mcp tools` now use the canonical
  evidence-first server.
- `mcp_server` still needs a future cleanup pass to split transport/install
  primitives away from legacy graph/KG/contest tools.

Canonical MCP tools are wrappers around core/adapters. They do not expose raw
shell execution. Proof execution is scoped through the EVM adapter/Forge helper,
not a generic command runner.

## Cleanup Priorities

1. Promote only evidence-backed pieces from `sequencer`, `simulator`,
   `validation`, and `invariants` into `core` or `adapters/evm`.
2. Move old `adversarial`, `monitor`, and `rl` packages under an explicit
   `experimental` namespace in a later milestone.
3. Split `mcp_server` into shared MCP primitives/installers and a deprecated
   legacy server package.
4. Keep README and CLI help aligned with stable capability only.

## Nested Directory Notes

These nested directories inherit the classification of their parent module:

| Directory | Parent classification | Notes | Action |
|---|---|---|---|
| `adversarial/agents` | experimental/legacy | Old role-specific swarm agents. | Keep experimental. |
| `contest/platforms` | experimental | Platform renderers used by old contest mode. | Keep experimental until evidence-gated. |
| `invariants/detectors` | legacy/experimental | Old detector set. Some detector ideas may be worth moving into adapters/core. | Merge selectively later. |
| `sequencer/builders` | proof/backend experimental | Old transaction path builders. | Keep experimental. |
| `sequencer/codegen` | proof/backend experimental | Old Foundry/Hardhat generation. | Merge useful parts later. |
| `templates/agent` | CLI/interface | Agent-facing template package data. | Keep; review wording. |
| `templates/pocs` | proof/backend | PoC template package data. | Keep; improve concrete generation. |
| `templates/reports` | reporting | Report template package data. | Keep if judge-gated. |
| `__pycache__` directories | remove | Local interpreter caches, not source modules. | Ignore/delete locally; never track. |
