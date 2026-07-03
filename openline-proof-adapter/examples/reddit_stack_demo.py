#!/usr/bin/env python3
"""Reddit-shaped demo for OpenLine Proof Adapter.

Shows four common production failures:
- runaway tool retries
- silent workflow changes
- lossy agent handoff
- destructive action without approval
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openline_proof_adapter import BoundaryEvent, PolicyConfig, ProofAdapter, ReceiptLog, verify_chain


DEMO_SIGNER_KEY = "demo-witness-key-change-me"
DEMO_KEY_ID = "demo-local-witness"


def run_demo(receipts_path: str = "receipts.jsonl") -> dict:
    path = Path(receipts_path)
    path.write_text("", encoding="utf-8")

    adapter = ProofAdapter(
        receipts_path=receipts_path,
        config=PolicyConfig(
            max_same_tool_calls=2,
            token_budget=2_000,
            handoff_required_terms={"without", "pip", "conda"},
        ),
        signer_key=DEMO_SIGNER_KEY,
        key_id=DEMO_KEY_ID,
    )

    decisions = []

    # 1. Tool loop: same search call repeats until the brake trips.
    for index in range(3):
        decision, _ = adapter.observe(
            BoundaryEvent(
                run_id="demo-run",
                event_id=f"search-{index}",
                system="langgraph",
                event_type="tool_call",
                action="search",
                payload={"query": "latest news"},
                tokens_used=450,
            )
        )
        decisions.append(("tool_loop", decision.result, decision.policy, decision.claim))

    # 2. n8n-style workflow liveness/version proof.
    adapter.observe(
        BoundaryEvent(
            run_id="demo-run",
            event_id="workflow-baseline",
            system="n8n",
            event_type="workflow_state",
            action="snapshot_workflow",
            payload={
                "workflow_name": "lead_sync",
                "active": True,
                "workflow": {"nodes": ["webhook", "crm"], "edges": [["webhook", "crm"]]},
                "change_note": "baseline",
            },
        )
    )
    decision, _ = adapter.observe(
        BoundaryEvent(
            run_id="demo-run",
            event_id="workflow-silent-change",
            system="n8n",
            event_type="workflow_state",
            action="snapshot_workflow",
            payload={
                "workflow_name": "lead_sync",
                "active": True,
                "workflow": {"nodes": ["webhook", "crm", "slack"], "edges": [["webhook", "crm"]]},
            },
        )
    )
    decisions.append(("silent_change", decision.result, decision.policy, decision.claim))

    # 3. Handoff digest lost a hard constraint.
    decision, _ = adapter.observe(
        BoundaryEvent(
            run_id="demo-run",
            event_id="handoff-loss",
            system="crew-ai",
            event_type="handoff",
            action="handoff_to_builder",
            payload={
                "summary": "Create the Python runner using package installs.",
                "digest": "runner task, use Python",
            },
        )
    )
    decisions.append(("handoff_loss", decision.result, decision.policy, decision.claim))

    # 4. Destructive action needs approval.
    decision, _ = adapter.observe(
        BoundaryEvent(
            run_id="demo-run",
            event_id="send-email",
            system="mcp-email",
            event_type="tool_call",
            action="send_email",
            payload={"to": "customer@example.com", "body": "Automated follow-up"},
        )
    )
    decisions.append(("approval_gate", decision.result, decision.policy, decision.claim))

    receipts = ReceiptLog(receipts_path).load()
    return {
        "receipts": len(receipts),
        "chain_valid": verify_chain(receipts, public_key=adapter.public_key, key_id=DEMO_KEY_ID),
        "decisions": decisions,
        "red_count": sum(1 for _, result, _, _ in decisions if result == "red"),
        "amber_count": sum(1 for _, result, _, _ in decisions if result == "amber"),
        "green_count": sum(1 for _, result, _, _ in decisions if result == "green"),
    }


def main() -> int:
    report = run_demo()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
