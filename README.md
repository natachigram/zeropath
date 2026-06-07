# ZeroPath

ZeroPath is an evidence-first smart contract security research engine.

It is built for local use by humans and IDE agents in tools like Codex, Claude
Code, Cursor, Windsurf, and other MCP-compatible environments. The engine helps
an agent understand a protocol, generate exploit hypotheses, prove or reject
them, remember useful evidence, and export reports only when judge checks pass.

## What ZeroPath Is

- A local research engine for smart contract security work.
- CLI-first and MCP-compatible.
- Memory-backed through a project research ledger.
- Adapter-based, with EVM/Solidity as the first stable adapter.
- Evidence-gated: hypotheses are not findings.

## What ZeroPath Is Not

- It is not a generic Solidity scanner.
- It is not an autonomous auditor that should be trusted to report issues by itself.
- It is not a report-generation toy.
- It does not claim full multi-language support until adapters exist.
- It does not mark anything report-ready without concrete evidence.

The core rule is simple:

> LLMs can propose. ZeroPath must verify.

## Current Status

Stable:

- project initialization
- local project store under `.zeropath`
- EVM project detection
- lightweight EVM indexing
- protocol intent snapshots
- candidate lifecycle storage
- evidence ledger fields
- memory router
- CLI commands for the evidence-first workflow
- MCP scaffold and tool wrappers

Experimental:

- template-driven hypothesis generation
- Foundry PoC skeleton generation
- skeptical judge engine
- report export templates
- Solodit integration placeholder through the older knowledge modules

Planned:

- stronger Solidity parsing
- vector retrieval
- full Solodit ingestion
- live fork validation
- LSP and VS Code UI
- Move, Solana, Cairo, and CosmWasm adapters

## Architecture

ZeroPath is layered:

1. Core engine: schemas, storage, protocol intent, candidates, memory, evidence, judging, and reports.
2. CLI: human and automation interface.
3. MCP server: IDE-agent interface.
4. Adapters: language and VM-specific indexing and proof backends.
5. Memory system: project, finding, pattern, rejection, and research ledger entries.
6. Evidence store: SQLite plus human-readable JSON artifacts under `.zeropath`.
7. Templates and benchmarks: report, PoC, agent, and benchmark scaffolds.

The core engine does not assume Solidity. EVM/Solidity support lives behind
`zeropath.adapters.evm`.

## CLI Usage

Initialize project state:

```bash
zeropath init
```

Index an EVM/Solidity project:

```bash
zeropath ingest --repo .
```

Generate a protocol intent snapshot:

```bash
zeropath understand
```

Generate high-impact hypotheses:

```bash
zeropath hunt --mode critical --limit 5
```

Inspect candidates:

```bash
zeropath candidates list
zeropath candidates show ZP-001
```

Record concrete evidence and triage facts:

```bash
zeropath candidates evidence ZP-001 \
  --root-cause-lines \
  --attacker-path \
  --state-preconditions \
  --duplicate-risk low \
  --known-issue-risk none \
  --live-config-checked
```

Build a proof-state plan:

```bash
zeropath candidates plan ZP-001
```

Generate a proof skeleton and run Foundry if available:

```bash
zeropath prove ZP-001 --backend foundry
```

Run judge checks:

```bash
zeropath judge ZP-001
```

Export a report only after the judge marks it ready:

```bash
zeropath report ZP-001 --format code4rena
```

For a non-final draft:

```bash
zeropath report ZP-001 --format code4rena --draft
```

## MCP Usage

Start the evidence-first MCP server:

```bash
zeropath mcp
```

The MCP tools wrap core functionality. They do not expose arbitrary shell
execution. Tools that mutate project state require explicit `write_mode=true`.

Important MCP tools include:

- `zeropath_project_status`
- `zeropath_ingest_repo`
- `zeropath_get_protocol_intent`
- `zeropath_generate_attack_hypotheses`
- `zeropath_update_candidate_evidence`
- `zeropath_build_state_plan`
- `zeropath_generate_foundry_poc`
- `zeropath_run_poc`
- `zeropath_judge_candidate`
- `zeropath_export_report`
- `zeropath_memory_search`

Legacy MCP installer commands are still available:

```bash
zeropath mcp install
zeropath mcp serve
zeropath mcp tools
```

## Memory System

ZeroPath memory is a research ledger, not casual chatbot memory.

Memory can store:

- evidence-backed project facts
- protocol intents
- invariants
- rejected hypotheses with reasons
- judge decisions
- proof results
- known issues
- duplicate signals
- high-confidence exploit patterns

Speculation is rejected by default, especially for global memory. Rejected
hypotheses are saved when they include a reason because they prevent repeated
wasted work.

## Evidence Gating

Candidate readiness is based on checklist evidence:

- root cause lines present
- attacker path present
- reachable state preconditions present
- PoC or proof artifact present
- proof result recorded
- live or fork configuration checked
- impact or profit measured
- known issue and duplicate risk considered

No evidence means no finding.

## Adapter Model

Adapters own ecosystem-specific behavior:

- project detection
- parsing and indexing
- entrypoint extraction
- asset-flow extraction
- role and dependency extraction
- invariant suggestions
- PoC generation
- proof backend execution

Current stable adapter:

- EVM/Solidity, using lightweight file scans and regex heuristics.

Future adapter stubs:

- Move
- Solana/Rust
- CosmWasm
- Cairo/Starknet

## Anti-Spam Design

ZeroPath is designed to avoid the common LLM audit failure mode:

```text
code -> pattern match -> generic vulnerability label -> spam report
```

The intended flow is:

```text
docs + code + config + memory
-> protocol-specific invariant
-> required exploit state
-> transaction sequence
-> proof attempt
-> judge checks
-> report or reject
```

## Example Workflow

```bash
zeropath init
zeropath ingest --repo .
zeropath understand
zeropath hunt --mode critical --limit 5
zeropath candidates list
zeropath prove ZP-001 --backend foundry
zeropath judge ZP-001
zeropath report ZP-001 --format code4rena --draft
zeropath memory rejected
```

## Development

Install locally:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Run focused tests:

```bash
pytest tests/test_project.py tests/test_storage.py tests/test_memory.py tests/test_memory_router.py tests/test_candidates.py tests/test_judge.py tests/test_cli.py tests/test_evm_detector.py tests/test_schemas.py
```

## Safety Notes

- MCP does not expose a generic shell tool.
- Report export refuses final output unless judge checks pass.
- PoC generation writes to `.zeropath/artifacts/pocs` by default.
- Writing into project test directories is opt-in and refuses overwrites unless forced.
- Do not store secrets in memory or artifacts.
- Treat every generated candidate as a hypothesis until proven.
