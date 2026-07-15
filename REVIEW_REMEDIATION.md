# July 2026 Review Remediation

Controlling review: *OLP Competitive Positioning - Evidence-Graded Competitive
Positioning and Execution Report*, dated 15 July 2026.

## Finding 1: forgeable default development key

Resolved. `ProofAdapter` has no signing default. It requires exactly one explicit
Ed25519 key object/raw key or a mode-0600 key file. Arbitrary text is no longer
hashed into a signing key. The demo uses a fresh ephemeral key and declares that
it has no production authority.

Regression evidence:

- missing-key construction fails;
- text-seed construction fails;
- insecure key-file permissions fail;
- independent attacker signatures fail against the pinned receiver key.

## Finding 2: multiple run chains fail whole-log verification

Resolved. Every receipt carries a positive per-run sequence and parent hash.
Python and Node verifiers maintain separate chain state for each `run_id`, so
interleaved runs verify while gaps, wrong parents, duplicate event IDs, and
mutations fail. Adapter restart restores each run's last accepted parent.

## Finding 3: blocked workflow state becomes the next baseline

Resolved. Workflow state is promoted only when the signed disposition is
`COMMIT`. A denied candidate remains in the receipt trail with
`state_promoted: false`; it never replaces the last accepted workflow hash.
The promoted commitment is restored from the verified log after restart.

The direct regression is: authorized baseline -> unauthorized change -> same
unauthorized change. Both unauthorized observations remain `REJECTED / DENY`
before and after restart.

## Finding 4: private receipt format diverges from Wire Canon

Resolved at the wire-envelope boundary. The old `0.1-mvp` envelope is retired.
Version 0.2 uses OLP integer canonicalization, canonical-body SHA-256, Ed25519,
strict fields, explicit self/provisional trust labels, external key pinning,
and the shared receiver disposition vocabulary.

The receipt remains an adapter-specific derived profile. It does not claim to
be one of Wire Canon 0.1's capture kinds, and a strict capture verifier should
return unsupported profile rather than silently upgrade it. The exact profile,
schema, and independent Node verifier ship in this repository.

## Preserved history

The original v0.1 sample receipt log is preserved byte-for-byte at
`history/receipts-v0.1.0.jsonl`, SHA-256
`d1b766218accdda2de3f951634d15fc1b9f80e8b301ebf2c6a31bc1474d70614`.
The new loader refuses to append v0.2 records to that historical format.

## Verification result

- 26 unit and hostile tests passed;
- 7 of 7 release gates passed;
- clean install from an unrelated directory passed;
- independent Node recomputation passed;
- extracted root-ready archive passed the same release gate.

These results repair the cited repository defects. They do not establish an
independent capture boundary, evidence truth, complete event coverage,
production key custody, or a security audit.
