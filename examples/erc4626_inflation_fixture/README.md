# ERC4626 Inflation Fixture

This is a tiny, intentionally vulnerable Foundry fixture for validating the
ZeroPath evidence-first workflow.

The vault uses `totalAssets()` as the raw token balance of the vault and has no
virtual shares, dead shares, or internal asset accounting. An attacker can seed
the vault with one wei, donate assets directly to skew the share price, cause a
victim deposit to mint zero shares, and then redeem the attacker's single share
for the victim's assets.

Run the ground-truth proof directly:

```bash
forge test
```

Run the ZeroPath workflow from this directory:

```bash
zeropath init
zeropath ingest --repo .
zeropath understand
zeropath hunt --mode critical --limit 5
zeropath candidates list
zeropath candidates show ZP-001
zeropath prove ZP-001 --backend foundry --no-run
zeropath judge ZP-001
zeropath report ZP-001 --format code4rena
```

Expected behavior: ZeroPath should identify the project as vault-like, generate
a share-inflation hypothesis, produce a useful proof skeleton with vault
entrypoint hints, and refuse final report export until evidence is manually
completed and judged.
