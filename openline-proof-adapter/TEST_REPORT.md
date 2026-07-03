# Test Report

Verification date: 2026-07-03

## Commands

```bash
python3 -m unittest discover -s tests -v
python3 examples/reddit_stack_demo.py
```

## Unit Tests

Result: pass

```text
Ran 14 tests in 0.013s
OK
```

Coverage by behavior:

- repeated tool-call loop gets a red receipt
- token budget guard returns amber before surprise spend
- workflow silent change gets a red receipt
- inactive workflow gets a red receipt
- lossy handoff triggers pullback
- destructive action requires approval
- receipt hash chain verifies and detects tampering
- forged receipts fail attested verification without the witness key
- public-key verifiers cannot forge the next receipt
- high-risk handoff terms use word-boundary matching
- near-repeat tool calls trip the loop brake
- configured fingerprints allow legitimate multi-city search comparisons
- non-JSON-serializable payloads still receive receipts

## Demo Result

```json
{
  "amber_count": 1,
  "chain_valid": true,
  "green_count": 2,
  "receipts": 7,
  "red_count": 3
}
```

The demo emits receipts for four Reddit-shaped agent-stack failures:

- retry loop
- silent workflow change
- lossy handoff
- unapproved destructive action

The receipt trail commits what crossed the boundary. With the pinned witness
public key, it also attests which witness issued the receipt. It does not prove
the underlying claim is true.
