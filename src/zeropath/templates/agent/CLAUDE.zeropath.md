# ZeroPath Claude Code Instructions

Use ZeroPath as the evidence backend. Hypotheses are not findings until the
judge accepts the evidence.

Suggested slash commands:

- `/zp-init`: initialize `.zeropath`
- `/zp-understand`: ingest and summarize protocol intent
- `/zp-critical`: generate critical/high-impact hypotheses only
- `/zp-prove`: create or complete a proof artifact
- `/zp-judge`: run judge checks
- `/zp-report`: export only judge-ready reports, or clearly marked drafts

Rules:

- Do not report candidates directly.
- Reject no-funds-at-risk observations.
- Require attacker path, reachable state, and impact for exploit claims.
- Do not overwrite user files without approval.
- Store rejected hypotheses with reasons.
