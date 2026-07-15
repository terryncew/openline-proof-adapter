"""Small proof adapter for existing agent and workflow stacks.

The adapter watches boundary events from systems such as n8n, LangGraph,
CrewAI, AutoGen, MCP tools, or plain Python functions. It emits compact signed
boundary assessment receipts and can ask the caller to block risky execution.
The caller remains responsible for enforcing that decision before a side
effect occurs.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .receipt import (
    Decision,
    Disposition,
    Receipt,
    ReceiptLog,
    Verdict,
    issue_receipt,
    load_private_key,
    load_private_key_file,
    public_key_hex,
    sha256,
    verify_chain,
)


EventType = Literal[
    "tool_call",
    "tool_result",
    "handoff",
    "workflow_state",
    "model_call",
    "approval",
]


DESTRUCTIVE_ACTIONS = {
    "send_email",
    "delete_record",
    "delete_file",
    "write_file",
    "modify_crm",
    "charge_card",
    "spend_money",
    "deploy",
    "publish",
}


@dataclass(frozen=True)
class BoundaryEvent:
    run_id: str
    event_id: str
    system: str
    event_type: EventType
    action: str
    payload: dict[str, Any]
    tokens_used: int = 0
    approved: bool = False


@dataclass(frozen=True)
class AdapterDecision:
    verdict: Verdict
    disposition: Disposition
    claim: str
    policy: str
    next_use_note: str
    should_block: bool = False
    should_pullback: bool = False

    @property
    def result(self) -> Decision:
        """Backward-compatible color view of the explicit disposition."""

        if self.disposition == "COMMIT":
            return "green"
        if self.disposition == "QUARANTINE":
            return "amber"
        return "red"


@dataclass
class PolicyConfig:
    max_same_tool_calls: int = 3
    token_budget: int = 12_000
    require_approval_for: set[str] = field(default_factory=lambda: set(DESTRUCTIVE_ACTIONS))
    handoff_required_terms: set[str] = field(default_factory=set)
    high_risk_terms: set[str] = field(
        default_factory=lambda: {"without", "never", "do not", "must", "except", "only"}
    )
    loop_fingerprint_fields: dict[str, set[str]] = field(default_factory=dict)


class ProofAdapter:
    def __init__(
        self,
        *,
        receipts_path: str = "receipts.jsonl",
        config: PolicyConfig | None = None,
        witness: str = "openline-proof-adapter",
        signer_key: bytes | Ed25519PrivateKey | None = None,
        signer_key_path: str | Path | None = None,
        key_id: str | None = None,
    ) -> None:
        if (signer_key is None) == (signer_key_path is None):
            raise ValueError("provide exactly one of signer_key or signer_key_path")
        resolved_key = (
            load_private_key_file(signer_key_path)
            if signer_key_path is not None
            else load_private_key(signer_key)
        )
        self.log = ReceiptLog(receipts_path)
        self.config = config or PolicyConfig()
        self.witness = witness
        self.signer_key = resolved_key
        self.public_key = public_key_hex(resolved_key)
        self.key_id = key_id or f"ed25519:{self.public_key[:24]}"
        self._parent_hash_by_run: dict[str, str | None] = defaultdict(lambda: None)
        self._sequence_by_run: dict[str, int] = defaultdict(int)
        self._tool_counts: dict[tuple[str, str], int] = defaultdict(int)
        self._tokens_by_run: dict[str, int] = defaultdict(int)
        self._workflow_hash_by_name: dict[str, str] = {}

        existing = self.log.load()
        if existing and not verify_chain(
            existing,
            public_key=self.public_key,
            key_id=self.key_id,
        ):
            raise ValueError(
                "existing receipt log failed signature or per-run chain verification; "
                "refusing to append"
            )
        for receipt in existing:
            self._parent_hash_by_run[receipt.run_id] = receipt.payload_hash
            self._sequence_by_run[receipt.run_id] = receipt.sequence
            self._tokens_by_run[receipt.run_id] += receipt.tokens_used
            tool_intent_hash = receipt.control.get("tool_intent_hash")
            if tool_intent_hash is not None:
                self._tool_counts[(receipt.run_id, str(tool_intent_hash))] += 1
            if receipt.control.get("state_promoted") is True:
                workflow_name = str(receipt.control["workflow_name"])
                self._workflow_hash_by_name[workflow_name] = str(
                    receipt.control["workflow_state_hash"]
                )

    def observe(self, event: BoundaryEvent) -> tuple[AdapterDecision, Receipt]:
        decision = self.decide(event)
        parent_hash = self._parent_hash_by_run[event.run_id]
        sequence = self._sequence_by_run[event.run_id] + 1
        receipt = issue_receipt(
            run_id=event.run_id,
            event_id=event.event_id,
            system=event.system,
            event_type=event.event_type,
            action=event.action,
            claim=decision.claim,
            evidence=event.payload,
            verdict=decision.verdict,
            disposition=decision.disposition,
            witness=self.witness,
            signer_key=self.signer_key,
            tokens_used=event.tokens_used,
            next_use_note=decision.next_use_note,
            parent_hash=parent_hash,
            sequence=sequence,
            policy=self._policy_descriptor(decision.policy),
            control=self._control_record(event, decision),
            key_id=self.key_id,
        )
        self.log.append(receipt)
        self._parent_hash_by_run[event.run_id] = receipt.payload_hash
        self._sequence_by_run[event.run_id] = receipt.sequence
        self._commit_state(event, decision)
        return decision, receipt

    def decide(self, event: BoundaryEvent) -> AdapterDecision:
        if event.action in self.config.require_approval_for and not event.approved:
            return AdapterDecision(
                verdict="REJECTED",
                disposition="DENY",
                claim=f"{event.action} requires approval before execution.",
                policy="approval_gate",
                next_use_note="Block execution until a human or trusted controller approves.",
                should_block=True,
            )

        if event.event_type == "tool_call":
            next_count = self._tool_counts[(event.run_id, self._tool_counter_key(event))] + 1
            projected_tokens = self._tokens_by_run[event.run_id] + event.tokens_used
            if next_count > self.config.max_same_tool_calls:
                return AdapterDecision(
                    verdict="REJECTED",
                    disposition="DENY",
                    claim="Repeated tool call pattern indicates a possible runaway loop.",
                    policy="loop_brake",
                    next_use_note="Stop the run, inspect the last tool result, then retry with a new plan.",
                    should_block=True,
                )
            if projected_tokens > self.config.token_budget:
                return AdapterDecision(
                    verdict="REJECTED",
                    disposition="QUARANTINE",
                    claim="Run is approaching or exceeding the configured token budget.",
                    policy="budget_guard",
                    next_use_note="Ask for approval, reduce context, or switch to a cheaper path.",
                    should_block=True,
                )

        if event.event_type == "handoff":
            return self._decide_handoff(event)

        if event.event_type == "workflow_state":
            return self._decide_workflow_state(event)

        return AdapterDecision(
            verdict="VERIFIED",
            disposition="COMMIT",
            claim="Boundary event recorded with no active policy violation.",
            policy="record_only",
            next_use_note="Receipt can be used for audit, replay, or downstream handoff.",
        )

    def _decide_handoff(self, event: BoundaryEvent) -> AdapterDecision:
        text = self._handoff_text(event.payload)
        missing = sorted(
            term for term in self.config.handoff_required_terms if not self._contains_term(text, term)
        )
        high_risk_present = any(self._contains_term(text, term) for term in self.config.high_risk_terms)
        if missing:
            return AdapterDecision(
                verdict="UNDECIDABLE",
                disposition="QUARANTINE",
                claim=f"Handoff digest is missing required term(s): {', '.join(missing)}.",
                policy="handoff_pullback",
                next_use_note="Pull fuller context before the next agent acts.",
                should_pullback=True,
            )
        if high_risk_present and len(text.split()) < 18:
            return AdapterDecision(
                verdict="UNDECIDABLE",
                disposition="QUARANTINE",
                claim="Handoff contains high-risk constraint language but too little context.",
                policy="handoff_pullback",
                next_use_note="Pull fuller context before acting on a hard constraint.",
                should_pullback=True,
            )
        return AdapterDecision(
            verdict="VERIFIED",
            disposition="COMMIT",
            claim="Handoff digest preserved required context for the next agent.",
            policy="handoff_digest",
            next_use_note="Proceed with digest; pull full record before irreversible action.",
        )

    def _decide_workflow_state(self, event: BoundaryEvent) -> AdapterDecision:
        workflow_name = str(event.payload.get("workflow_name", event.system))
        state_hash = self._workflow_state_hash(event)
        previous_hash = self._workflow_hash_by_name.get(workflow_name)
        active = event.payload.get("active")
        change_note = str(event.payload.get("change_note", "")).strip()
        if previous_hash is not None and previous_hash != state_hash and not change_note:
            return AdapterDecision(
                verdict="REJECTED",
                disposition="DENY",
                claim=f"Workflow {workflow_name} changed without a change note.",
                policy="silent_change_guard",
                next_use_note="Alert owner, record diff, and require a change receipt.",
                should_block=True,
            )
        if active is False:
            return AdapterDecision(
                verdict="REJECTED",
                disposition="DENY",
                claim=f"Workflow {workflow_name} is inactive.",
                policy="silent_break_guard",
                next_use_note="Alert owner before assuming the automation is running.",
                should_block=True,
            )
        return AdapterDecision(
            verdict="VERIFIED",
            disposition="COMMIT",
            claim=f"Workflow {workflow_name} state recorded.",
            policy="workflow_watch",
            next_use_note="Use receipt as version and liveness evidence.",
        )

    def _commit_state(self, event: BoundaryEvent, decision: AdapterDecision) -> None:
        self._tokens_by_run[event.run_id] += event.tokens_used
        if event.event_type == "tool_call":
            self._tool_counts[(event.run_id, self._tool_counter_key(event))] += 1
        if event.event_type == "workflow_state" and decision.disposition == "COMMIT":
            workflow_name = str(event.payload.get("workflow_name", event.system))
            self._workflow_hash_by_name[workflow_name] = self._workflow_state_hash(event)

    def _control_record(
        self,
        event: BoundaryEvent,
        decision: AdapterDecision,
    ) -> dict[str, Any]:
        if event.event_type == "tool_call":
            return {"tool_intent_hash": self._tool_counter_key(event)}
        if event.event_type == "workflow_state":
            return {
                "workflow_name": str(event.payload.get("workflow_name", event.system)),
                "workflow_state_hash": self._workflow_state_hash(event),
                "state_promoted": decision.disposition == "COMMIT",
            }
        return {}

    def _policy_descriptor(self, policy_id: str) -> dict[str, Any]:
        return {
            "id": policy_id,
            "version": "0.2",
            "snapshot": {
                "max_same_tool_calls": self.config.max_same_tool_calls,
                "token_budget": self.config.token_budget,
                "require_approval_for": sorted(self.config.require_approval_for),
                "handoff_required_terms": sorted(self.config.handoff_required_terms),
                "high_risk_terms": sorted(self.config.high_risk_terms),
                "loop_fingerprint_fields": {
                    key: sorted(value)
                    for key, value in sorted(self.config.loop_fingerprint_fields.items())
                },
            },
        }

    def _workflow_state_hash(self, event: BoundaryEvent) -> str:
        return sha256(event.payload.get("workflow", event.payload))

    def _tool_counter_key(self, event: BoundaryEvent) -> str:
        return sha256(self._tool_intent_key(event))

    def _tool_key(self, event: BoundaryEvent) -> str:
        args = event.payload.get("args", event.payload)
        return f"{event.system}:{event.action}:{sha256(args)}"

    def _tool_intent_key(self, event: BoundaryEvent) -> str:
        payload = event.payload.get("args", event.payload)
        configured_fields = self._loop_fingerprint_fields(event)
        if configured_fields:
            field_parts = []
            for field_path in sorted(configured_fields):
                field_parts.append(f"{field_path}={self._field_value(payload, field_path)}")
            return f"{event.system}:{event.action}:fields:{sha256(field_parts)}"
        text = " ".join(self._extract_text(payload))
        terms = [
            token
            for token in re.findall(r"[a-z0-9]+", text.lower())
            if token
            not in {
                "a",
                "an",
                "and",
                "again",
                "for",
                "in",
                "now",
                "please",
                "the",
                "to",
                "today",
                "with",
            }
        ]
        return f"{event.system}:{event.action}:{' '.join(terms[:4])}"

    def _loop_fingerprint_fields(self, event: BoundaryEvent) -> set[str]:
        return (
            self.config.loop_fingerprint_fields.get(f"{event.system}.{event.action}")
            or self.config.loop_fingerprint_fields.get(event.action)
            or set()
        )

    def _field_value(self, payload: Any, field_path: str) -> Any:
        current = payload
        for part in field_path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    def _handoff_text(self, payload: dict[str, Any]) -> str:
        return re.sub(r"\s+", " ", str(payload).lower())

    def _contains_term(self, text: str, term: str) -> bool:
        escaped = re.escape(term.lower())
        return bool(re.search(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])", text))

    def _extract_text(self, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            text: list[str] = []
            for key, inner in value.items():
                text.append(str(key))
                text.extend(self._extract_text(inner))
            return text
        if isinstance(value, list | tuple | set | frozenset):
            text = []
            for inner in value:
                text.extend(self._extract_text(inner))
            return text
        return [str(value)]
