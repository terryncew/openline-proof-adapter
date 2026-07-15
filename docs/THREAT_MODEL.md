# Threat Model

## Covered

- modification of any signed receipt field;
- forged receipts signed by an untrusted key;
- interleaved per-run logs;
- sequence gaps, wrong parents, and duplicate event IDs within a run;
- accidental use of the old public deterministic development key;
- group/world-readable local key files;
- repeated loop and budget state after a process restart;
- denied workflow state being promoted into the trusted baseline;
- duplicate JSON keys and unsupported canonical values;
- raw event payload leakage through the v0.2 receipt profile.

## Trust boundary

The adapter runs with the system it observes. Its receipts are `self` attested
and `provisional`. A valid signature establishes key possession and integrity,
not truth, complete capture, operator independence, or correct policy.

The authorized public key must be pinned outside the receipt. The key embedded
in a receipt is discovery data, not a trust anchor.

## Outside scope

- host compromise that can replace the private key, code, log, and external
  trust configuration together;
- log truncation before an independently retained anchor exists;
- cross-process concurrent writers racing to issue the next receipt for one
  run;
- proof that every consequential event was observed;
- truth or semantic sufficiency of the evidence hash;
- automatic reversal of actions that already happened;
- production key rotation, HSM/KMS custody, retention, or external anchoring;
- independent receiver witnessing.

Use Receipt Gate when a receiver needs a full proof-to-policy decision across
integrity, provenance, coverage, freshness, evidence, and outcome dimensions.
This adapter provides local boundary assessment and a portable signed record;
it does not replace that appraisal.

