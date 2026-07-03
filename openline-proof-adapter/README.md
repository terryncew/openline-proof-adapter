# OpenLine Proof Adapter

Portable OLP-style receipts for the messy agent stack people already use.

This is not another agent framework. It sits beside n8n, LangGraph, CrewAI,
AutoGen, MCP tools, LangSmith, Langfuse, and plain Python. It watches boundary
events and writes small receipts before the stack burns money, loses context,
silently changes, or touches something it should not touch.

Core line:

> A log shows what happened inside one tool.  
> A receipt travels across the stack.

## What It Replaces

- random logs
- screenshots as proof
- manual QA notes
- static prompt evals
- after-the-fact trace archaeology
- "trust me bro" agent claims

## What It Enhances

- LangSmith / Langfuse: add portable regression and guard receipts
- LangGraph: add signed retry, handoff, and budget receipts
- n8n: add workflow liveness, version, and silent-change receipts
- MCP tools: add signed tool-call receipts and permission gates
- CrewAI / AutoGen: add loop brakes and handoff pullback receipts
- local agents: add one receipt format across model providers

## What It Catches

The demo and tests cover four Reddit-shaped production failures:

1. A tool call repeats until the run starts burning money.
2. An n8n-style workflow changes or goes inactive without a useful record.
3. A handoff digest loses a hard constraint.
4. A destructive action tries to run without approval.

Each event produces a compact OLP-style receipt:

```json
{
  "kind": "olp_proof_adapter_receipt",
  "run_id": "demo-run",
  "system": "langgraph",
  "action": "search",
  "claim": "Repeated tool call pattern indicates a possible runaway loop.",
  "evidence_hash": "sha256...",
  "result": "red",
  "witness": "openline-proof-adapter",
  "parent_hash": "sha256...",
  "key_id": "local-witness",
  "payload_hash": "sha256...",
  "signature": {
    "algorithm": "ed25519",
    "public_key": "...",
    "value": "..."
  }
}
```

The receipt commits what crossed the boundary. With the pinned witness public
key, it also attests which witness issued it. It does not prove the underlying
claim is true.

## Quickstart

Run the demo:

```bash
python3 examples/reddit_stack_demo.py
```

Run tests:

```bash
python3 -m unittest discover -s tests -v
```

Use it in plain Python:

```python
from openline_proof_adapter import BoundaryEvent, PolicyConfig, ProofAdapter

adapter = ProofAdapter(
    receipts_path="receipts.jsonl",
    signer_key="replace-with-your-ed25519-private-seed",
    key_id="local-witness",
    config=PolicyConfig(
        max_same_tool_calls=2,
        token_budget=2000,
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

Verify an attested chain:

```python
from openline_proof_adapter import ReceiptLog, verify_chain

receipts = ReceiptLog("receipts.jsonl").load()
assert verify_chain(receipts, public_key=adapter.public_key, key_id="local-witness")
```

Hash-only integrity checks are available as `verify_receipt_integrity` and
`verify_chain_integrity`, but they do not prove witness identity.

Loop detection can be tuned for legitimate parameter sweeps:

```python
PolicyConfig(loop_fingerprint_fields={"search": {"query"}})
```

That keeps repeated identical searches catchable while allowing a real
multi-city search comparison to proceed.

## Public Demo Claim

Most agent stacks already have traces.

What they lack is standing.

OpenLine Proof Adapter turns fragile agent events into portable receipts that
can survive outside the tool that created them.

Small receipts. Big accountability.
