# Boundary Assessment Receipt Profile 0.2

Status: Repaired experimental adapter profile

Schema: `schemas/boundary-assessment-receipt.schema.json`

## Relationship to OLP Wire Canon

This profile uses the byte-level rules from OLP Wire Canon 0.1:

- canonicalization: `olp-canonical-json-int-v1`;
- payload hash: lowercase SHA-256 over the canonical body after removing
  exactly `payload_hash` and `signature`;
- signature: Ed25519 directly over the same canonical body;
- integer domain: `[-9007199254740991, 9007199254740991]`;
- trust labels: `attestation: self` and `capture_status: provisional`.

The implementation was checked against public Wire Canon commit
`3607996396e4a647213a4a67bc62d4ae07f998f4`.

`proof_adapter_boundary_assessment_receipt` is a derived adapter profile. It is
not one of Wire Canon 0.1's four registered capture kinds. A strict Wire Canon
0.1 capture verifier should report the profile as unsupported, even when its
envelope signature is valid. The Proof Adapter verifier checks this profile;
the independent Node verifier recomputes the same bytes and per-run chains.

This distinction prevents a policy assessment from being relabeled as capture
proof.

## Signed body

Every receipt contains:

- profile and canonicalization identifiers;
- explicit self/provisional trust labels;
- issuer ID and key ID;
- event ID, system, type, and action;
- claim and raw-evidence-excluding evidence hash;
- `VERIFIED`, `REJECTED`, or `UNDECIDABLE` verdict;
- `COMMIT`, `QUARANTINE`, `DENY`, `NO_BADGE`, or `ROLLBACK_REQUEST`
  disposition;
- policy identity and policy hash;
- control commitments needed to restore loop, budget, and workflow-baseline
  state;
- token usage;
- run ID, positive per-run sequence, and previous receipt hash;
- next-use note and privacy declaration.

Raw evidence is excluded. Evidence normalization is identified as
`proof-adapter-evidence-json-v1`. It preserves ordinary JSON values, sorts
sets, encodes bytes as lowercase hexadecimal, and wraps large integers and
finite binary64 values explicitly before hashing. Non-finite numbers and
unsupported application objects are rejected.

## Chain semantics

One JSONL log may interleave independent runs. Verification maintains
`expected_sequence`, `expected_parent_hash`, and observed event IDs separately
for each `run_id`.

For each run:

1. the first receipt has sequence 1 and parent `null`;
2. each later receipt increments sequence by one;
3. each later parent equals the immediately preceding payload hash;
4. an event ID cannot repeat.

Log order is preserved, but a receipt from another run does not become the
parent of the current run.

## Trust rule

The embedded public key verifies mathematical integrity only. A verifier must
receive an authorized public key through separate receiver-controlled
configuration. Verifying against the key copied from the receipt proves no
identity and no authority.

## State promotion rule

Every workflow snapshot carries its candidate state hash. `state_promoted` may
be true only when the disposition is `COMMIT`. On restart, the adapter restores
the latest promoted workflow commitment and ignores denied candidates as
baselines. The denied receipts remain in the chain as evidence of the attempt.

