# Changelog

## 0.2.0 - 2026-07-15

- Removed the deterministic default signing key and all text-to-key derivation.
- Added exclusive mode-0600 Ed25519 key generation and loading.
- Added OLP integer-canonical signed boundary assessment receipts with explicit
  self/provisional trust labels and receiver disposition vocabulary.
- Added strict receipt profile validation and duplicate-key rejection.
- Fixed whole-log verification for interleaved per-run chains.
- Added per-run sequence and duplicate-event checks.
- Restored per-run chain, loop, budget, and promoted workflow state after
  process restart.
- Prevented denied workflow snapshots from becoming the next trusted baseline.
- Added an independent Node verifier and hostile mutation/duplicate-key tests.
- Preserved the original sample log under `history/`.

## 0.1.0 - 2026-07-03

- Initial proof-adapter prototype.
