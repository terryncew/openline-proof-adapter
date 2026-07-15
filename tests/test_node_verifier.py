import hashlib
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openline_proof_adapter import BoundaryEvent, PolicyConfig, ProofAdapter


ROOT = Path(__file__).resolve().parents[1]
NODE_VERIFIER = ROOT / "verify-receipts-node.mjs"


class IndependentNodeVerifierTests(unittest.TestCase):
    key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"proof-adapter-node-conformance-key").digest()
    )

    def make_log(self, path: Path) -> ProofAdapter:
        adapter = ProofAdapter(
            receipts_path=str(path),
            config=PolicyConfig(handoff_required_terms=set()),
            signer_key=self.key,
            key_id="node-conformance-key",
        )
        for run_id, event_id in (
            ("run-a", "a-1"),
            ("run-b", "b-1"),
            ("run-a", "a-2"),
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
        return adapter

    def run_node(self, path: Path, public_key: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["node", str(NODE_VERIFIER), str(path), "--trusted-key", public_key],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_node_verifies_interleaved_multi_run_log(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "receipts.jsonl"
            adapter = self.make_log(path)
            completed = self.run_node(path, adapter.public_key)
            self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
            report = json.loads(completed.stdout)
            self.assertTrue(report["valid"])
            self.assertEqual(report["count"], 3)
            self.assertEqual(report["run_count"], 2)

    def test_node_rejects_mutated_signed_body(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "receipts.jsonl"
            adapter = self.make_log(path)
            lines = path.read_text(encoding="ascii").splitlines()
            receipt = json.loads(lines[1])
            receipt["claim"] = "mutated after signing"
            lines[1] = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
            path.write_text("\n".join(lines) + "\n", encoding="ascii")
            completed = self.run_node(path, adapter.public_key)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("payload_hash_mismatch", completed.stdout)

    def test_node_rejects_duplicate_json_key(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "receipts.jsonl"
            adapter = self.make_log(path)
            lines = path.read_text(encoding="ascii").splitlines()
            lines[0] = lines[0].replace(
                "{",
                '{"kind":"proof_adapter_boundary_assessment_receipt",',
                1,
            )
            path.write_text("\n".join(lines) + "\n", encoding="ascii")
            completed = self.run_node(path, adapter.public_key)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("duplicate JSON key", completed.stdout)


if __name__ == "__main__":
    unittest.main()
