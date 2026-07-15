# Test Report - v0.2.0

Verification date: 2026-07-15

## Result

```text
26 tests passed
7 of 7 release gates passed
clean install from an unrelated directory passed
independent Node verification passed
```

Commands:

```bash
python -m unittest discover -s tests -v
python examples/reddit_stack_demo.py
python scripts/release_check.py
```

## Review finding coverage

### Deterministic default key

- construction without a key fails;
- text passphrases are rejected;
- generated key files are exclusive and mode `0600`;
- overly broad key-file permissions are rejected;
- the demo uses a fresh in-memory key with no production authority.

### Multiple run chains in one log

- interleaved runs verify in Python;
- the same log verifies independently in Node;
- each run has its own sequence and parent;
- duplicate event IDs, gaps, wrong parents, body mutation, and duplicate JSON
  keys are rejected;
- adapter restart continues the existing per-run chain.

### Blocked workflow state

- a denied snapshot is recorded but never promoted;
- repeating the same unauthorized snapshot remains denied;
- the behavior survives adapter restart;
- only a `COMMIT` receipt may set `state_promoted: true`.

### Wire discipline

- v0.2 uses `olp-canonical-json-int-v1`;
- payload hash and Ed25519 signature cover the same canonical body;
- trust remains explicitly `self` and `provisional`;
- the schema is strict and raw event payloads are excluded;
- `VERIFIED`, `REJECTED`, and `UNDECIDABLE` remain separate from the five
  Receipt Gate dispositions;
- the adapter profile is documented as derived rather than misrepresented as a
  core Wire Canon 0.1 capture kind.

## Additional regression coverage

- loop brake and near-repeat detection;
- configurable intent fingerprints;
- token-budget quarantine;
- handoff pullback and word-boundary matching;
- approval denial for destructive actions;
- authorized-key verification and attacker-key rejection;
- deterministic hashing for supported non-JSON evidence values;
- preservation and explicit refusal to extend the historical v0.1 log.

## Claim boundary

These results establish internal consistency, clean package execution, and
cross-language recomputation for the repaired profile. They do not establish
production security, independent capture, evidence truth, complete event
coverage, market demand, or safety under host compromise.
