import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openline_proof_adapter import (
    BoundaryEvent,
    PolicyConfig,
    ProofAdapter,
    ReceiptLog,
    UnsupportedReceiptVersion,
    generate_private_key_file,
    load_private_key_file,
    validate_receipt_profile,
    verify_chain,
    verify_chain_integrity,
    verify_receipt,
    verify_receipt_integrity,
)
from openline_proof_adapter.receipt import issue_receipt


class ProofAdapterTests(unittest.TestCase):
    signer_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"proof-adapter-test-key").digest()
    )
    attacker_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"proof-adapter-attacker-key").digest()
    )

    def make_adapter(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "receipts.jsonl"
        adapter = ProofAdapter(
            receipts_path=str(path),
            config=PolicyConfig(
                max_same_tool_calls=2,
                token_budget=1_000,
                handoff_required_terms={"without", "pip", "conda"},
            ),
            signer_key=self.signer_key,
            key_id="test-key",
        )
        return adapter, path

    def verify_adapter_receipt(self, receipt):
        return verify_receipt(receipt, public_key=receipt.signature["public_key"], key_id="test-key")

    def test_loop_brake_blocks_repeated_tool_call(self):
        adapter, _ = self.make_adapter()
        results = []
        for index in range(3):
            decision, receipt = adapter.observe(
                BoundaryEvent(
                    run_id="run-loop",
                    event_id=f"search-{index}",
                    system="langgraph",
                    event_type="tool_call",
                    action="search",
                    payload={"query": "latest news"},
                    tokens_used=100,
                )
            )
            self.assertTrue(verify_receipt(receipt, public_key=receipt.signature["public_key"], key_id="test-key"))
            results.append(decision.result)
        self.assertEqual(results, ["green", "green", "red"])

    def test_budget_guard_blocks_before_surprise_bill(self):
        adapter, _ = self.make_adapter()
        first, _ = adapter.observe(
            BoundaryEvent(
                run_id="run-budget",
                event_id="call-1",
                system="openai-agents",
                event_type="tool_call",
                action="research",
                payload={"topic": "market scan"},
                tokens_used=900,
            )
        )
        second, _ = adapter.observe(
            BoundaryEvent(
                run_id="run-budget",
                event_id="call-2",
                system="openai-agents",
                event_type="tool_call",
                action="summarize",
                payload={"source": "large transcript"},
                tokens_used=250,
            )
        )
        self.assertEqual(first.result, "green")
        self.assertEqual(second.result, "amber")
        self.assertTrue(second.should_block)

    def test_workflow_silent_change_gets_red_receipt(self):
        adapter, _ = self.make_adapter()
        adapter.observe(
            BoundaryEvent(
                run_id="run-workflow",
                event_id="baseline",
                system="n8n",
                event_type="workflow_state",
                action="snapshot_workflow",
                payload={
                    "workflow_name": "lead_sync",
                    "active": True,
                    "workflow": {"nodes": ["webhook", "crm"]},
                    "change_note": "baseline",
                },
            )
        )
        decision, _ = adapter.observe(
            BoundaryEvent(
                run_id="run-workflow",
                event_id="changed",
                system="n8n",
                event_type="workflow_state",
                action="snapshot_workflow",
                payload={
                    "workflow_name": "lead_sync",
                    "active": True,
                    "workflow": {"nodes": ["webhook", "crm", "slack"]},
                },
            )
        )
        self.assertEqual(decision.result, "red")
        self.assertEqual(decision.policy, "silent_change_guard")

    def test_inactive_workflow_gets_red_receipt(self):
        adapter, _ = self.make_adapter()
        decision, _ = adapter.observe(
            BoundaryEvent(
                run_id="run-inactive",
                event_id="inactive",
                system="n8n",
                event_type="workflow_state",
                action="snapshot_workflow",
                payload={
                    "workflow_name": "lead_sync",
                    "active": False,
                    "workflow": {"nodes": ["webhook", "crm"]},
                    "change_note": "disabled accidentally",
                },
            )
        )
        self.assertEqual(decision.result, "red")
        self.assertEqual(decision.policy, "silent_break_guard")

    def test_handoff_missing_constraint_triggers_pullback(self):
        adapter, _ = self.make_adapter()
        decision, _ = adapter.observe(
            BoundaryEvent(
                run_id="run-handoff",
                event_id="handoff",
                system="crewai",
                event_type="handoff",
                action="handoff_to_builder",
                payload={"summary": "Create the Python runner using package installs."},
            )
        )
        self.assertEqual(decision.result, "amber")
        self.assertTrue(decision.should_pullback)

    def test_destructive_action_requires_approval(self):
        adapter, _ = self.make_adapter()
        blocked, _ = adapter.observe(
            BoundaryEvent(
                run_id="run-email",
                event_id="email-1",
                system="mcp-email",
                event_type="tool_call",
                action="send_email",
                payload={"to": "customer@example.com"},
            )
        )
        allowed, _ = adapter.observe(
            BoundaryEvent(
                run_id="run-email",
                event_id="email-2",
                system="mcp-email",
                event_type="tool_call",
                action="send_email",
                payload={"to": "customer@example.com"},
                approved=True,
            )
        )
        self.assertEqual(blocked.result, "red")
        self.assertEqual(allowed.result, "green")

    def test_receipt_chain_verifies_and_detects_tamper(self):
        adapter, path = self.make_adapter()
        for index in range(2):
            adapter.observe(
                BoundaryEvent(
                    run_id="run-chain",
                    event_id=f"event-{index}",
                    system="plain-python",
                    event_type="model_call",
                    action="answer",
                    payload={"index": index},
                )
            )
        receipts = ReceiptLog(path).load()
        self.assertTrue(verify_chain(receipts, public_key=receipts[0].signature["public_key"], key_id="test-key"))
        tampered = [*receipts]
        data = tampered[1].to_dict()
        data["claim"] = "quietly edited claim"
        tampered[1] = type(receipts[1])(**data)
        self.assertFalse(verify_chain(tampered, public_key=receipts[0].signature["public_key"], key_id="test-key"))

    def test_forged_receipt_fails_attested_verification(self):
        forged = issue_receipt(
            run_id="forged-run",
            event_id="forged-1",
            system="mcp-email",
            action="send_email",
            claim="send_email approved by CFO",
            evidence={"approved": True},
            result="green",
            witness="openline-proof-adapter",
            signer_key=self.attacker_key,
            key_id="test-key",
        )
        chained = issue_receipt(
            run_id="forged-run",
            event_id="forged-2",
            system="mcp-email",
            action="send_email",
            claim="second forged event",
            evidence={"approved": True},
            result="green",
            witness="openline-proof-adapter",
            signer_key=self.attacker_key,
            key_id="test-key",
            parent_hash=forged.payload_hash,
            sequence=2,
        )
        self.assertTrue(verify_chain_integrity([forged, chained]))
        real_adapter, _ = self.make_adapter()
        self.assertFalse(verify_chain([forged, chained], public_key=real_adapter.public_key, key_id="test-key"))
        self.assertTrue(verify_chain([forged, chained], public_key=forged.signature["public_key"], key_id="test-key"))

    def test_public_key_verifier_cannot_forge_next_receipt(self):
        adapter, _ = self.make_adapter()
        decision, first = adapter.observe(
            BoundaryEvent(
                run_id="run-public-key",
                event_id="event-1",
                system="plain-python",
                event_type="model_call",
                action="answer",
                payload={"message": "real receipt"},
            )
        )
        self.assertEqual(decision.result, "green")
        forged = issue_receipt(
            run_id="run-public-key",
            event_id="event-2",
            system="mcp-email",
            action="send_email",
            claim="send_email approved by CFO",
            evidence={"approved": True},
            result="green",
            witness="openline-proof-adapter",
            signer_key=self.attacker_key,
            key_id="test-key",
            parent_hash=first.payload_hash,
        )
        self.assertFalse(verify_chain([first, forged], public_key=adapter.public_key, key_id="test-key"))

    def test_high_risk_terms_use_word_boundaries(self):
        adapter, path = self.make_adapter()
        decision, receipt = adapter.observe(
            BoundaryEvent(
                run_id="run-boundary",
                event_id="handoff",
                system="crewai",
                event_type="handoff",
                action="handoff_to_builder",
                payload={"summary": "Delivered exceptional service quality today"},
            )
        )
        self.assertEqual(decision.result, "amber")
        self.assertEqual(decision.policy, "handoff_pullback")

        adapter = ProofAdapter(
            receipts_path=str(path.parent / "receipts2.jsonl"),
            config=PolicyConfig(max_same_tool_calls=2, handoff_required_terms=set()),
            signer_key=self.signer_key,
            key_id="test-key",
        )
        decision, _ = adapter.observe(
            BoundaryEvent(
                run_id="run-boundary-2",
                event_id="handoff",
                system="crewai",
                event_type="handoff",
                action="handoff_to_builder",
                payload={"summary": "Delivered exceptional service quality today"},
            )
        )
        self.assertEqual(decision.result, "green")

    def test_near_repeat_tool_calls_trip_loop_brake(self):
        adapter, _ = self.make_adapter()
        results = []
        for index, query in enumerate(
            [
                "latest news please",
                "latest news now",
                "latest news today",
            ]
        ):
            decision, _ = adapter.observe(
                BoundaryEvent(
                    run_id="run-near-loop",
                    event_id=f"search-{index}",
                    system="langgraph",
                    event_type="tool_call",
                    action="search",
                    payload={"query": query},
                    tokens_used=100,
                )
            )
            results.append(decision.result)
        self.assertEqual(results, ["green", "green", "red"])

    def test_non_json_serializable_payload_gets_receipt(self):
        adapter, path = self.make_adapter()
        decision, receipt = adapter.observe(
            BoundaryEvent(
                run_id="run-set",
                event_id="event-set",
                system="plain-python",
                event_type="model_call",
                action="answer",
                payload={"seen": {"alpha", "beta"}},
            )
        )
        self.assertEqual(decision.result, "green")
        self.assertTrue(verify_receipt(receipt, public_key=receipt.signature["public_key"], key_id="test-key"))
        receipts = ReceiptLog(path).load()
        self.assertEqual(len(receipts), 1)
        self.assertTrue(verify_receipt(receipts[0], public_key=adapter.public_key, key_id="test-key"))

    def test_configured_fingerprint_allows_multi_city_search(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        adapter = ProofAdapter(
            receipts_path=str(Path(tmp.name) / "receipts.jsonl"),
            config=PolicyConfig(
                max_same_tool_calls=2,
                token_budget=5_000,
                handoff_required_terms=set(),
                loop_fingerprint_fields={"search": {"query"}},
            ),
            signer_key=self.signer_key,
            key_id="test-key",
        )
        results = []
        for index, query in enumerate(
            [
                "flight options new york to tokyo",
                "flight options new york to paris",
                "flight options new york to berlin",
            ]
        ):
            decision, _ = adapter.observe(
                BoundaryEvent(
                    run_id="run-flights",
                    event_id=f"search-{index}",
                    system="langgraph",
                    event_type="tool_call",
                    action="search",
                    payload={"query": query},
                    tokens_used=100,
                )
            )
            results.append(decision.result)
        self.assertEqual(results, ["green", "green", "green"])

    def test_configured_fingerprint_still_catches_exact_repeat(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        adapter = ProofAdapter(
            receipts_path=str(Path(tmp.name) / "receipts.jsonl"),
            config=PolicyConfig(
                max_same_tool_calls=2,
                token_budget=5_000,
                handoff_required_terms=set(),
                loop_fingerprint_fields={"search": {"query"}},
            ),
            signer_key=self.signer_key,
            key_id="test-key",
        )
        results = []
        for index in range(3):
            decision, _ = adapter.observe(
                BoundaryEvent(
                    run_id="run-repeat-query",
                    event_id=f"search-{index}",
                    system="langgraph",
                    event_type="tool_call",
                    action="search",
                    payload={"query": "flight options new york to tokyo"},
                    tokens_used=100,
                )
            )
            results.append(decision.result)
        self.assertEqual(results, ["green", "green", "red"])

    def test_signing_key_is_required_and_text_seeds_are_rejected(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "receipts.jsonl"
            with self.assertRaisesRegex(ValueError, "exactly one"):
                ProofAdapter(receipts_path=str(path))
            with self.assertRaisesRegex(TypeError, "text passphrases"):
                ProofAdapter(receipts_path=str(path), signer_key="guessable-text-seed")

    def test_private_key_file_is_exclusive_and_mode_0600(self):
        with TemporaryDirectory() as directory:
            key_path = Path(directory) / "keys" / "adapter.key"
            public_key = generate_private_key_file(key_path)
            self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(public_key), 64)
            adapter = ProofAdapter(
                receipts_path=str(Path(directory) / "receipts.jsonl"),
                signer_key_path=key_path,
            )
            self.assertEqual(adapter.public_key, public_key)
            with self.assertRaises(FileExistsError):
                generate_private_key_file(key_path)

            os.chmod(key_path, 0o644)
            with self.assertRaises(PermissionError):
                load_private_key_file(key_path)

    def test_receipt_uses_wire_canon_envelope_and_receiver_disposition(self):
        adapter, _ = self.make_adapter()
        decision, receipt = adapter.observe(
            BoundaryEvent(
                run_id="run-envelope",
                event_id="event-1",
                system="mcp-email",
                event_type="tool_call",
                action="send_email",
                payload={"to": "customer@example.com"},
            )
        )
        validate_receipt_profile(receipt)
        self.assertEqual(decision.verdict, "REJECTED")
        self.assertEqual(decision.disposition, "DENY")
        self.assertEqual(receipt.kind, "proof_adapter_boundary_assessment_receipt")
        self.assertEqual(receipt.receipt_version, "0.2")
        self.assertEqual(receipt.canonicalization_id, "olp-canonical-json-int-v1")
        self.assertEqual(receipt.attestation, "self")
        self.assertEqual(receipt.capture_status, "provisional")
        self.assertEqual(receipt.signature["algorithm"], "Ed25519")
        self.assertEqual(receipt.privacy, {"raw_evidence_stored": False})
        self.assertEqual(receipt.policy["snapshot"]["policy_id"], "approval_gate")
        self.assertEqual(receipt.policy["snapshot"]["token_budget"], 1_000)
        self.assertNotIn("to", receipt.to_dict())

    def test_interleaved_multi_run_log_verifies(self):
        adapter, path = self.make_adapter()
        for run_id, event_id in (
            ("run-a", "a-1"),
            ("run-b", "b-1"),
            ("run-a", "a-2"),
            ("run-b", "b-2"),
        ):
            adapter.observe(
                BoundaryEvent(
                    run_id=run_id,
                    event_id=event_id,
                    system="plain-python",
                    event_type="model_call",
                    action="answer",
                    payload={"event": event_id},
                )
            )
        receipts = ReceiptLog(path).load()
        self.assertEqual([receipt.sequence for receipt in receipts], [1, 1, 2, 2])
        self.assertTrue(verify_chain_integrity(receipts))
        self.assertTrue(
            verify_chain(receipts, public_key=adapter.public_key, key_id="test-key")
        )

    def test_duplicate_event_id_in_one_run_breaks_chain_semantics(self):
        first = issue_receipt(
            run_id="duplicate-run",
            event_id="event-1",
            system="plain-python",
            action="answer",
            claim="first",
            evidence={"value": 1},
            result="green",
            witness="openline-proof-adapter",
            signer_key=self.signer_key,
            key_id="test-key",
        )
        second = issue_receipt(
            run_id="duplicate-run",
            event_id="event-1",
            system="plain-python",
            action="answer",
            claim="duplicate",
            evidence={"value": 2},
            result="green",
            witness="openline-proof-adapter",
            signer_key=self.signer_key,
            key_id="test-key",
            sequence=2,
            parent_hash=first.payload_hash,
        )
        self.assertFalse(
            verify_chain([first, second], public_key=first.signature["public_key"], key_id="test-key")
        )

    def test_adapter_restart_continues_chain_and_loop_state(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "receipts.jsonl"
            config = PolicyConfig(
                max_same_tool_calls=2,
                token_budget=5_000,
                handoff_required_terms=set(),
            )
            adapter = ProofAdapter(
                receipts_path=str(path),
                config=config,
                signer_key=self.signer_key,
                key_id="test-key",
            )
            for index in range(2):
                decision, _ = adapter.observe(
                    BoundaryEvent(
                        run_id="restart-run",
                        event_id=f"event-{index}",
                        system="langgraph",
                        event_type="tool_call",
                        action="search",
                        payload={"query": "latest news"},
                        tokens_used=100,
                    )
                )
                self.assertEqual(decision.result, "green")

            restarted = ProofAdapter(
                receipts_path=str(path),
                config=config,
                signer_key=self.signer_key,
                key_id="test-key",
            )
            decision, receipt = restarted.observe(
                BoundaryEvent(
                    run_id="restart-run",
                    event_id="event-2",
                    system="langgraph",
                    event_type="tool_call",
                    action="search",
                    payload={"query": "latest news"},
                    tokens_used=100,
                )
            )
            self.assertEqual(decision.result, "red")
            self.assertEqual(receipt.sequence, 3)
            self.assertTrue(
                verify_chain(
                    ReceiptLog(path).load(),
                    public_key=restarted.public_key,
                    key_id="test-key",
                )
            )

    def test_blocked_workflow_state_never_becomes_baseline(self):
        adapter, _ = self.make_adapter()
        baseline = BoundaryEvent(
            run_id="workflow-run",
            event_id="baseline",
            system="n8n",
            event_type="workflow_state",
            action="snapshot_workflow",
            payload={
                "workflow_name": "lead_sync",
                "active": True,
                "workflow": {"nodes": ["webhook", "crm"]},
                "change_note": "authorized baseline",
            },
        )
        adapter.observe(baseline)
        unauthorized_payload = {
            "workflow_name": "lead_sync",
            "active": True,
            "workflow": {"nodes": ["webhook", "crm", "exfil"]},
        }
        results = []
        receipts = []
        for index in range(2):
            decision, receipt = adapter.observe(
                BoundaryEvent(
                    run_id="workflow-run",
                    event_id=f"unauthorized-{index}",
                    system="n8n",
                    event_type="workflow_state",
                    action="snapshot_workflow",
                    payload=unauthorized_payload,
                )
            )
            results.append(decision.result)
            receipts.append(receipt)
        self.assertEqual(results, ["red", "red"])
        self.assertTrue(all(receipt.control["state_promoted"] is False for receipt in receipts))

    def test_blocked_workflow_state_stays_blocked_after_restart(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "receipts.jsonl"
            config = PolicyConfig(handoff_required_terms=set())
            adapter = ProofAdapter(
                receipts_path=str(path),
                config=config,
                signer_key=self.signer_key,
                key_id="test-key",
            )
            adapter.observe(
                BoundaryEvent(
                    run_id="workflow-run",
                    event_id="baseline",
                    system="n8n",
                    event_type="workflow_state",
                    action="snapshot_workflow",
                    payload={
                        "workflow_name": "lead_sync",
                        "active": True,
                        "workflow": {"nodes": ["webhook", "crm"]},
                        "change_note": "authorized baseline",
                    },
                )
            )
            changed = {
                "workflow_name": "lead_sync",
                "active": True,
                "workflow": {"nodes": ["webhook", "crm", "exfil"]},
            }
            first, _ = adapter.observe(
                BoundaryEvent(
                    run_id="workflow-run",
                    event_id="unauthorized-1",
                    system="n8n",
                    event_type="workflow_state",
                    action="snapshot_workflow",
                    payload=changed,
                )
            )
            restarted = ProofAdapter(
                receipts_path=str(path),
                config=config,
                signer_key=self.signer_key,
                key_id="test-key",
            )
            second, _ = restarted.observe(
                BoundaryEvent(
                    run_id="workflow-run",
                    event_id="unauthorized-2",
                    system="n8n",
                    event_type="workflow_state",
                    action="snapshot_workflow",
                    payload=changed,
                )
            )
            self.assertEqual((first.result, second.result), ("red", "red"))

    def test_historical_receipt_log_is_preserved_but_cannot_be_extended(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.jsonl"
            path.write_text(
                json.dumps({"kind": "olp_proof_adapter_receipt", "receipt_version": "0.1-mvp"})
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(UnsupportedReceiptVersion):
                ProofAdapter(
                    receipts_path=str(path),
                    signer_key=self.signer_key,
                    key_id="test-key",
                )


if __name__ == "__main__":
    unittest.main()
