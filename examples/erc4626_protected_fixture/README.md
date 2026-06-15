# ERC4626 Protected Vault Fixture

A donation-resistant vault used to exercise ZeroPath's **anti-condition**
(inflation-mitigation) detection. It is the inverse of
`examples/erc4626_inflation_fixture/`.

`ProtectedVault` defeats the classic donation/first-deposit share inflation
attack with two well-known mitigations:

- **Internal asset accounting** — `totalAssets()` returns a tracked `_totalAssets`
  counter instead of `asset.balanceOf(address(this))`, so a direct token donation
  to the vault does not move the share price.
- **Virtual shares (decimals offset)** — share/asset conversion adds
  `10 ** _DECIMALS_OFFSET` virtual shares and `+ 1` virtual assets, so a tiny first
  deposit cannot inflate the price-per-share.

Expected ZeroPath behavior: the vault is still detected as vault-like and a
share-inflation *candidate* may be generated, but the judge must **not** mark it
report-ready. `zeropath.core.inflation_guards.detect_share_inflation_guards`
flags `virtual_shares` and `internal_accounting`, and the judge blocks the
candidate with a clearly-marked heuristic anti-condition objection.

Source-only fixture: there is no Foundry project here because anti-condition
detection is a static source scan and does not run `forge`.
