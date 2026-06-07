# ZeroPath Agent Instructions

Use ZeroPath as the evidence backend for smart contract security research.

- Do not report candidate findings directly.
- Always call `zeropath_judge_candidate` before writing a final report.
- Prefer critical-only mode unless the user asks for QA or low severity.
- Reject observations with no meaningful funds at risk.
- For exploit claims, require attacker path, reachable state, and concrete impact.
- Use generated PoCs as starting points, then make them runnable.
- Do not overwrite user files without approval or explicit write mode.
- Store rejected hypotheses with reasons to avoid repeated work.
- Always distinguish hypothesis from proof.
- Never call a hypothesis a vulnerability.
