"""
MCP prompt templates — pre-built audit workflows.

A prompt in MCP is a structured message sequence the IDE agent can
load on demand (e.g. via a slash command). For ZeroPath these encode
the audit workflows in a way that gives the IDE's LLM the right
system prompt + the right tool-call sequence to follow.

Every prompt returns a ``messages`` array per the MCP spec. The agent
inserts those messages into its conversation and starts acting on
them, calling our tools as needed.
"""

from __future__ import annotations

from typing import Any

from zeropath.mcp_server.server import Prompt


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------


def _prompt_contest_audit() -> Prompt:
    def handler(args: dict[str, Any]) -> list[dict[str, Any]]:
        platform = args.get("platform", "cantina")
        repo_path = args.get("repo_path", "./contracts")
        scope = args.get("scope_files", "")

        user_msg = (
            f"Audit this {platform} contest. Repo: `{repo_path}`. "
            f"{'Scope: ' + scope if scope else 'Scope: every .sol under src/.'}\n\n"
            "Use ZeroPath tools in this order:\n"
            "1. `analyze_protocol` on the repo path to build the protocol graph.\n"
            "2. `infer_invariants` (min_severity=medium) to surface Phase-2 findings.\n"
            "3. `mine_spec_claims` to extract NatSpec + README invariants.\n"
            "4. `kg_summary` so you know what historical bug classes are over-represented.\n"
            "5. For each likely bug class, call "
            "`query_kg_historical_grounding` and use the matched incidents as "
            "context for your reasoning.\n"
            "6. Construct PoC Foundry tests for every CRITICAL or HIGH "
            "candidate and call `verify_foundry_poc` — only submit findings "
            "whose PoC actually compiles and asserts profit.\n"
            "7. For every validated finding call "
            "`estimate_duplicate_likelihood` — submit low-dup findings first.\n"
            "8. Call `format_finding_for_platform` to render the final "
            f"submission shape for `{platform}`.\n\n"
            "Hard rules:\n"
            " - Don't submit a finding whose PoC doesn't pass `verify_foundry_poc`.\n"
            " - Don't submit findings with confidence < 0.70.\n"
            " - Prefer spec/implementation gaps (mine_spec_claims) — they "
            "are usually low duplicate likelihood.\n"
            " - Spec/impl mismatches that align with Phase-2 invariants are "
            "gold."
        )
        return [{"role": "user", "content": {"type": "text", "text": user_msg}}]

    return Prompt(
        name="contest_audit",
        description=(
            "Run a full audit-contest workflow against a target repo. "
            "Drives the IDE agent through ZeroPath's analyze → infer → "
            "spec-mine → KG-ground → PoC-verify → format pipeline."
        ),
        arguments=[
            {"name": "platform", "description": "cantina | code4rena | sherlock | immunefi", "required": False},
            {"name": "repo_path", "description": "Path to the contest repo (default ./contracts)", "required": False},
            {"name": "scope_files", "description": "Comma-separated relative paths in scope", "required": False},
        ],
        handler=handler,
    )


def _prompt_spec_extract() -> Prompt:
    def handler(args: dict[str, Any]) -> list[dict[str, Any]]:
        repo_path = args.get("repo_path", "./contracts")
        msg = (
            f"Mine the docs + NatSpec in `{repo_path}` for claimed invariants. "
            "Call `mine_spec_claims` with that path. For each returned claim, "
            "trace the relevant function in the source and judge whether the "
            "code actually enforces the claim. Report mismatches — those are "
            "candidate findings."
        )
        return [{"role": "user", "content": {"type": "text", "text": msg}}]

    return Prompt(
        name="spec_extract",
        description=(
            "Extract every claimed invariant from NatSpec + README + docs "
            "and check the implementation against each claim. Spec/impl "
            "gaps are a high-payoff bug class in audits."
        ),
        arguments=[
            {"name": "repo_path", "description": "Repository root", "required": False},
        ],
        handler=handler,
    )


def _prompt_contrarian_review() -> Prompt:
    def handler(args: dict[str, Any]) -> list[dict[str, Any]]:
        finding_json = args.get("finding_json", "")
        msg = (
            "You are a contest judge reviewing a submitted finding. "
            "Your job is to REJECT it if you can. Specifically check:\n"
            " 1. Is the attack path actually executable on mainnet, or "
            "does a precondition like `attacker == owner` defeat it?\n"
            " 2. Does the PoC compile + run? Call `verify_foundry_poc` "
            "with the code if needed.\n"
            " 3. Is there an overlooked safeguard (modifier, guard, pause)?\n"
            " 4. Is the severity inflated relative to real impact?\n"
            " 5. Could this be a known historical class — query the KG "
            "with `query_kg_similar_exploits` to check.\n\n"
            "Output one JSON object: "
            "{verdict: accept|reject|escalate, objections: [...], "
            "downgrade_severity_to: critical|high|medium|low|null, "
            "recommendation: submit|rewrite|discard}.\n\n"
            f"Finding under review:\n```json\n{finding_json}\n```"
        )
        return [{"role": "user", "content": {"type": "text", "text": msg}}]

    return Prompt(
        name="contrarian_review",
        description=(
            "Apply contest-judge skepticism to a finding. Returns a strict "
            "JSON verdict + objections + severity-downgrade suggestion."
        ),
        arguments=[
            {"name": "finding_json", "description": "Serialised SubmissionFinding", "required": True},
        ],
        handler=handler,
    )


def _prompt_kg_grounding() -> Prompt:
    def handler(args: dict[str, Any]) -> list[dict[str, Any]]:
        attack_class = args.get("attack_class", "oracle_manipulation")
        contracts = args.get("contracts", "")
        msg = (
            f"Look up historical precedents for a `{attack_class}` attack "
            f"{'on contracts: ' + contracts if contracts else ''}. "
            "Call `query_kg_historical_grounding` with the attack class "
            "and contract names. Use the returned incidents as context for "
            "your audit — match the attack patterns against the current "
            "codebase and report any that line up."
        )
        return [{"role": "user", "content": {"type": "text", "text": msg}}]

    return Prompt(
        name="kg_ground_attack_class",
        description=(
            "Surface historical precedents from the KG for a given "
            "attack class + contract set. Use early in an audit to seed "
            "your hypotheses with real-world patterns."
        ),
        arguments=[
            {"name": "attack_class", "description": "Phase 3 attack class enum", "required": True},
            {"name": "contracts", "description": "Comma-separated contract names", "required": False},
        ],
        handler=handler,
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_default_prompts(server) -> None:
    """Wire every default prompt onto the server."""
    for build in (
        _prompt_contest_audit,
        _prompt_spec_extract,
        _prompt_contrarian_review,
        _prompt_kg_grounding,
    ):
        server.add_prompt(build())
