# Initializer Takeover Fixture

A minimal upgradeable-style vault whose `initialize` function is unprotected:
it has no one-time guard, no constructor lockout, and no access control, so any
caller can run `initialize(attacker)` and become `owner` — then use owner-only
controls such as `sweep`.

This is the second concrete vertical proven end to end by ZeroPath (after the
ERC4626 inflation fixture), validating the bug-class-agnostic proof spine:

```bash
zeropath init
zeropath ingest --repo .
zeropath hunt --mode critical --limit 5
zeropath prove ZP-001 --backend foundry   # generates + runs an executable PoC
zeropath judge ZP-001                      # report-ready only after the PoC passes
zeropath report ZP-001 --format code4rena
```

`zeropath prove` generates a Foundry test that calls the open `initialize` from
an untrusted caller and asserts the caller seized ownership
(`attackerBecameOwner == 1`). The judge marks it report-ready only after the
proof passes; the report includes initializer-specific mitigations.

The inverse (protected) shape — an `initializer` modifier, `_disableInitializers()`
in the constructor, or a re-init flag guard — is detected by
`zeropath.core.initializer_guards` as an anti-condition and blocks the candidate
unless a passing PoC overrides the heuristic.

Scope note: the proof template assumes a no-arg constructor and an
`initialize(address)` that sets an `owner()` — the benchmark fixture shape, not
a general UUPS/Beacon proxy PoC.
