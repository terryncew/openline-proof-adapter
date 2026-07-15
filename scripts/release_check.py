#!/usr/bin/env python3
"""Run the v0.2 release gates from source and a clean package install."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap


ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_RECEIPT_SHA256 = "d1b766218accdda2de3f951634d15fc1b9f80e8b301ebf2c6a31bc1474d70614"


def run(
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def main() -> int:
    gates: dict[str, bool] = {}
    details: dict[str, object] = {}

    unit = run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT,
    )
    unit_output = unit.stdout + unit.stderr
    gates["unit_and_hostile_tests"] = unit.returncode == 0 and "Ran 26 tests" in unit_output
    details["unit_test_summary"] = "Ran 26 tests" if "Ran 26 tests" in unit_output else "unavailable"

    try:
        schema = json.loads(
            (ROOT / "schemas" / "boundary-assessment-receipt.schema.json").read_text(
                encoding="utf-8"
            )
        )
        gates["schema_document_valid"] = (
            schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
            and schema.get("properties", {}).get("kind", {}).get("const")
            == "proof_adapter_boundary_assessment_receipt"
        )
    except (OSError, json.JSONDecodeError):
        gates["schema_document_valid"] = False

    history = (ROOT / "history" / "receipts-v0.1.0.jsonl").read_bytes()
    history_hash = hashlib.sha256(history).hexdigest()
    gates["v010_history_preserved"] = history_hash == HISTORICAL_RECEIPT_SHA256
    details["historical_receipt_sha256"] = history_hash

    production_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            ROOT / "openline_proof_adapter" / "adapter.py",
            ROOT / "openline_proof_adapter" / "receipt.py",
            ROOT / "examples" / "reddit_stack_demo.py",
        )
    )
    gates["no_known_development_signing_key"] = all(
        marker not in production_text
        for marker in (
            "-".join(("dev", "only", "change", "me")),
            "-".join(("demo", "witness", "key", "change", "me")),
        )
    )

    with tempfile.TemporaryDirectory() as directory:
        temporary = Path(directory)
        site = temporary / "site"
        install_environment = os.environ.copy()
        install_environment["PIP_CACHE_DIR"] = str(temporary / "pip-cache")
        install = run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-deps",
                "--no-build-isolation",
                "--target",
                str(site),
                str(ROOT),
            ],
            cwd=temporary,
            env=install_environment,
        )
        gates["clean_install"] = install.returncode == 0
        details["clean_install_returncode"] = install.returncode

        installed_log = temporary / "installed-receipts.jsonl"
        installed_script = textwrap.dedent(
            f"""
            import json
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from openline_proof_adapter import BoundaryEvent, PolicyConfig, ProofAdapter, ReceiptLog, verify_chain

            key = Ed25519PrivateKey.generate()
            adapter = ProofAdapter(
                receipts_path={str(installed_log)!r},
                config=PolicyConfig(handoff_required_terms=set()),
                signer_key=key,
                key_id="clean-install-key",
            )
            for run_id, event_id in (("run-a", "a-1"), ("run-b", "b-1"), ("run-a", "a-2")):
                adapter.observe(BoundaryEvent(
                    run_id=run_id,
                    event_id=event_id,
                    system="plain-python",
                    event_type="model_call",
                    action="answer",
                    payload={{"event": event_id}},
                ))
            receipts = ReceiptLog({str(installed_log)!r}).load()
            print(json.dumps({{
                "public_key": adapter.public_key,
                "count": len(receipts),
                "python_valid": verify_chain(receipts, public_key=adapter.public_key, key_id="clean-install-key"),
            }}))
            """
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(site)
        installed = run(
            [sys.executable, "-c", installed_script],
            cwd=temporary,
            env=environment,
        ) if install.returncode == 0 else None
        try:
            installed_report = json.loads(installed.stdout) if installed is not None else {}
        except json.JSONDecodeError:
            installed_report = {}
        gates["installed_package_issues_and_verifies"] = bool(
            installed is not None
            and installed.returncode == 0
            and installed_report.get("count") == 3
            and installed_report.get("python_valid") is True
        )

        trusted_key = str(installed_report.get("public_key", ""))
        node = run(
            [
                "node",
                str(ROOT / "verify-receipts-node.mjs"),
                str(installed_log),
                "--trusted-key",
                trusted_key,
            ],
            cwd=temporary,
        ) if len(trusted_key) == 64 else None
        try:
            node_report = json.loads(node.stdout) if node is not None else {}
        except json.JSONDecodeError:
            node_report = {}
        gates["independent_node_verification"] = bool(
            node is not None
            and node.returncode == 0
            and node_report.get("valid") is True
            and node_report.get("count") == 3
            and node_report.get("run_count") == 2
        )
        details["installed_node_report"] = {
            key: node_report.get(key)
            for key in ("valid", "count", "run_count", "errors")
        }

    result = {
        "schema": "openline.proof_adapter.release_check.v0.2",
        "version": "0.2.0",
        "passed": all(gates.values()),
        "passed_gate_count": sum(int(value) for value in gates.values()),
        "gate_count": len(gates),
        "gates": gates,
        "details": details,
        "claim_boundary": (
            "These gates show internal consistency, clean package execution, and independent "
            "recomputation of the repaired receipt and per-run chain behavior. They do not "
            "establish production security, independent capture, evidence truth, or market demand."
        ),
    }
    (ROOT / "RUN_REPORT.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
