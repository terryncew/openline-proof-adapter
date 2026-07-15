# OpenLine Proof Adapter

> Portfolio status: **Repaired Experimental Adapter - v0.2.0**

OpenLine Proof Adapter watches boundary events from n8n, LangGraph, CrewAI,
AutoGen, MCP tools, and plain Python. It applies small local policies for loops,
budget pressure, handoff loss, workflow drift, and unapproved destructive
actions, then emits a signed receiver-owned assessment.

This repository is an adapter, not the Evidence Gateway or the Receipt Gate.
It does not establish that an event or claim is true, undo an upstream side
effect, or turn a self-attested observation into independent provenance.

## What v0.2 repairs

The July 2026 evidence-graded review identified four production blockers. This
release addresses each one:

1. **No default signing key.** Construction fails unless the caller supplies an
   Ed25519 key object, exactly 32 raw key bytes, or a mode-0600 key file. Text
   passphrases and deterministic development defaults are rejected.
2. **Interleaved runs verify correctly.** One JSONL file may contain multiple
   per-run chains. Python and independent Node verifiers track sequence,
   parent, and duplicate event IDs separately for each `run_id`.
3. **Denied state never becomes trusted state.** A workflow snapshot is promoted
   only after `COMMIT`. Repeating a denied snapshot remains denied, including
   after an adapter restart. The log records the exact promoted-state
   commitment used to restore that baseline.
4. **The private wire envelope is retired.** v0.2 uses
   `olp-canonical-json-int-v1`, SHA-256 over the canonical signed body, Ed25519,
   explicit `self` / `provisional` trust labels, strict fields, and the Receipt
   Gate disposition vocabulary. The adapter receipt is a documented derived
   profile; it does not masquerade as one of Wire Canon 0.1's capture kinds.

The original v0.1 sample log remains unchanged under
`history/receipts-v0.1.0.jsonl`. A v0.1 log is readable as raw history but cannot
be extended as a v0.2 chain.

## Decisions

The assessment and operational decision are separate:

```text
VERIFIED     -> COMMIT
UNDECIDABLE  -> QUARANTINE or NO_BADGE
REJECTED     -> QUARANTINE, DENY, NO_BADGE, or ROLLBACK_REQUEST
```

The current policies emit `COMMIT`, `QUARANTINE`, or `DENY`. The older
green/amber/red view remains available through `decision.result` and
`receipt.result` for migration only.

## Quickstart

Install and create a local key once:

```bash
python -m pip install -e .
python - <<'PY'
from openline_proof_adapter import generate_private_key_file
print(generate_private_key_file(".secrets/proof-adapter.key"))
PY
```

The key generator refuses to overwrite an existing file and creates it with
mode `0600`.

Use the adapter:

```python
from openline_proof_adapter import BoundaryEvent, PolicyConfig, ProofAdapter

adapter = ProofAdapter(
    receipts_path="receipts.jsonl",
    signer_key_path=".secrets/proof-adapter.key",
    key_id="receiver-proof-adapter-2026-01",
    config=PolicyConfig(
        max_same_tool_calls=2,
        token_budget=2_000,
        handoff_required_terms={"without", "pip", "conda"},
    ),
)

decision, receipt = adapter.observe(
    BoundaryEvent(
        run_id="run-1",
        event_id="tool-1",
        system="langgraph",
        event_type="tool_call",
        action="search",
        payload={"query": "latest news"},
        tokens_used=450,
    )
)

if decision.should_block:
    raise RuntimeError(decision.claim)
```

The key used to authorize verification must come from receiver-controlled
configuration. Never trust the public key merely because it appears inside the
receipt.

## Verify a mixed-run log

Python:

```python
from openline_proof_adapter import ReceiptLog, verify_chain

receipts = ReceiptLog("receipts.jsonl").load()
assert verify_chain(
    receipts,
    public_key=TRUSTED_RECEIVER_PUBLIC_KEY,
    key_id="receiver-proof-adapter-2026-01",
)
```

Independent Node verifier:

```bash
node verify-receipts-node.mjs receipts.jsonl \
  --trusted-key "$TRUSTED_RECEIVER_PUBLIC_KEY"
```

Hash-only checks remain available as `verify_receipt_integrity` and
`verify_chain_integrity`. They establish internal continuity, not signer
authority.

## Demo and release check

```bash
python examples/reddit_stack_demo.py
python -m unittest discover -s tests -v
python scripts/release_check.py
```

The demo creates a fresh in-memory key each time and labels it as having no
production authority. The release check performs a clean package install from
an unrelated directory and verifies its output independently in Node.

## Receipt boundary

The signed receipt contains the event identity, policy result, evidence hash,
usage count, per-run sequence and parent, and control-state commitments. Raw
event payloads are excluded.

Read [the receipt profile](docs/BOUNDARY_RECEIPT_PROFILE.md),
[migration guide](docs/MIGRATION.md), and
[threat model](docs/THREAT_MODEL.md) before relying on the output.

Small receipts. Big accountability.
