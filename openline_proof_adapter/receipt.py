"""Signed receipt primitives for OpenLine Proof Adapter.

Version 0.2 uses the OLP integer-canonical JSON and Ed25519 envelope rules.  It
is an adapter-specific derived profile, not one of Wire Canon 0.1's four
capture receipt kinds.  A signature proves integrity and possession of a key;
authority still comes from an externally pinned public key.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import struct
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


Decision = Literal["green", "amber", "red"]
Verdict = Literal["VERIFIED", "REJECTED", "UNDECIDABLE"]
Disposition = Literal["COMMIT", "QUARANTINE", "DENY", "NO_BADGE", "ROLLBACK_REQUEST"]

MAX_SAFE_INTEGER = (1 << 53) - 1
CANONICALIZATION_ID = "olp-canonical-json-int-v1"
RECEIPT_KIND = "proof_adapter_boundary_assessment_receipt"
RECEIPT_VERSION = "0.2"
ALGORITHM_ID = "openline-proof-adapter-boundary-0.2"
SPEC_URI = (
    "https://github.com/terryncew/openline-proof-adapter/"
    "blob/main/docs/BOUNDARY_RECEIPT_PROFILE.md"
)
WIRE_CANON_URI = "https://github.com/terryncew/olp-wire-canon"

HASH256 = re.compile(r"^[0-9a-f]{64}$")
SIGNATURE_HEX = re.compile(r"^[0-9a-f]{128}$")

_TOP_LEVEL_FIELDS = {
    "kind",
    "receipt_version",
    "algorithm_id",
    "canonicalization_id",
    "spec_uri",
    "wire_canon_uri",
    "attestation",
    "capture_status",
    "issuer",
    "created_at",
    "event",
    "claim",
    "evidence",
    "verdict",
    "decision",
    "policy",
    "control",
    "usage",
    "binding",
    "next_use_note",
    "privacy",
    "payload_hash",
    "signature",
}


class DuplicateKeyError(ValueError):
    """Raised when a JSON object repeats a key."""


class UnsupportedReceiptVersion(ValueError):
    """Raised when a log contains a historical receipt profile."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def strict_json_loads(text: str) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    return json.loads(
        text,
        object_pairs_hook=_strict_object,
        parse_constant=reject_constant,
    )


def _validate_canonical_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError(f"{path}: integer outside interoperable range")
        return
    if isinstance(value, float):
        raise ValueError(f"{path}: floats are forbidden")
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_canonical_value(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise ValueError(f"{path}: keys must be ASCII strings")
            _validate_canonical_value(item, f"{path}.{key}")
        return
    raise ValueError(f"{path}: unsupported value type {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Return OLP ``olp-canonical-json-int-v1`` text."""

    _validate_canonical_value(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def json_safe(value: Any) -> Any:
    """Normalize evidence before hashing without placing it in the receipt.

    Wire receipt bodies remain integer-only.  Large integers and binary64
    values use the same explicit wrapper convention as the OTel Wire Canon
    profile.  Sets are sorted by their normalized canonical representation.
    Unsupported application objects fail closed instead of being hashed from an
    unstable ``repr``.
    """

    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) <= MAX_SAFE_INTEGER:
            return value
        return {"$int": str(value)}
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite evidence values are unsupported")
        return {"$f64": struct.pack("!d", value).hex()}
    if isinstance(value, bytes):
        return {"$bytes": value.hex()}
    if isinstance(value, Mapping):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [json_safe(item) for item in value]
        return sorted(normalized, key=canonical_json)
    raise TypeError(f"unsupported evidence value type: {type(value).__name__}")


def evidence_canonical_json(value: Any) -> str:
    return canonical_json(json_safe(value))


def sha256(value: str | bytes | Any) -> str:
    if isinstance(value, bytes):
        data = value
    elif isinstance(value, str):
        data = value.encode("utf-8")
    else:
        data = evidence_canonical_json(value).encode("ascii")
    return hashlib.sha256(data).hexdigest()


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _coerce_private_key(value: bytes | Ed25519PrivateKey) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    if not isinstance(value, bytes):
        raise TypeError(
            "signer_key must be an Ed25519PrivateKey or exactly 32 raw bytes; "
            "text passphrases and deterministic default keys are forbidden"
        )
    if len(value) != 32:
        raise ValueError("raw Ed25519 private key must be exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(value)


def load_private_key(signer_key: bytes | Ed25519PrivateKey) -> Ed25519PrivateKey:
    """Load an explicit key without deriving one from a guessable string."""

    return _coerce_private_key(signer_key)


def generate_private_key_file(path: str | Path) -> str:
    """Create a mode-0600 raw Ed25519 key file and return its public key."""

    target = Path(path)
    if target.exists():
        raise FileExistsError(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(raw.hex() + "\n")
    return public_key_hex(key)


def load_private_key_file(path: str | Path) -> Ed25519PrivateKey:
    target = Path(path)
    mode = target.stat().st_mode & 0o777
    if mode & 0o077:
        raise PermissionError(f"private key must not be group/world accessible: {oct(mode)}")
    encoded = target.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", encoded):
        raise ValueError("private key file must contain 32-byte lowercase hex")
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(encoded))


def public_key_hex(signer_key: bytes | Ed25519PrivateKey) -> str:
    private_key = _coerce_private_key(signer_key)
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


def sign_body(
    body: dict[str, Any], signer_key: bytes | Ed25519PrivateKey
) -> dict[str, str]:
    private_key = _coerce_private_key(signer_key)
    message = canonical_json(body).encode("ascii")
    return {
        "algorithm": "Ed25519",
        "public_key": public_key_hex(private_key),
        "value": private_key.sign(message).hex(),
    }


def _normalize_public_key(public_key: str | bytes) -> str:
    encoded = public_key.hex() if isinstance(public_key, bytes) else public_key
    encoded = encoded.removeprefix("ed25519:")
    if not HASH256.fullmatch(encoded):
        raise ValueError("trusted public key must be 32-byte lowercase hex")
    return encoded


def verify_signature(
    body: dict[str, Any], signature: Mapping[str, Any], public_key: str | bytes
) -> bool:
    try:
        expected_public_key = _normalize_public_key(public_key)
        if signature.get("algorithm") != "Ed25519":
            return False
        if signature.get("public_key") != expected_public_key:
            return False
        signature_value = str(signature["value"])
        if not SIGNATURE_HEX.fullmatch(signature_value):
            return False
        verifier = Ed25519PublicKey.from_public_bytes(bytes.fromhex(expected_public_key))
        verifier.verify(bytes.fromhex(signature_value), canonical_json(body).encode("ascii"))
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False


@dataclass(frozen=True)
class Receipt:
    kind: str
    receipt_version: str
    algorithm_id: str
    canonicalization_id: str
    spec_uri: str
    wire_canon_uri: str
    attestation: str
    capture_status: str
    issuer: dict[str, str]
    created_at: str
    event: dict[str, str]
    claim: str
    evidence: dict[str, str]
    verdict: Verdict
    decision: Disposition
    policy: dict[str, Any]
    control: dict[str, Any]
    usage: dict[str, int]
    binding: dict[str, Any]
    next_use_note: str
    privacy: dict[str, bool]
    payload_hash: str
    signature: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def run_id(self) -> str:
        return str(self.binding["run_id"])

    @property
    def event_id(self) -> str:
        return str(self.event["id"])

    @property
    def system(self) -> str:
        return str(self.event["system"])

    @property
    def action(self) -> str:
        return str(self.event["action"])

    @property
    def evidence_hash(self) -> str:
        return str(self.evidence["hash"])

    @property
    def result(self) -> Decision:
        if self.decision == "COMMIT":
            return "green"
        if self.decision == "QUARANTINE":
            return "amber"
        return "red"

    @property
    def witness(self) -> str:
        return str(self.issuer["id"])

    @property
    def parent_hash(self) -> str | None:
        value = self.binding.get("parent_hash")
        return str(value) if value is not None else None

    @property
    def sequence(self) -> int:
        return int(self.binding["sequence"])

    @property
    def tokens_used(self) -> int:
        return int(self.usage["tokens_used"])

    @property
    def key_id(self) -> str:
        return str(self.issuer["key_id"])

    @property
    def note(self) -> str:
        return (
            "The signature proves integrity and possession of the configured key. "
            "The receipt is self-attested and provisional; it does not prove the "
            "event, evidence, or claim is true."
        )


def _policy_record(policy: str | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(policy, str):
        policy_id = policy
        version = RECEIPT_VERSION
        snapshot: dict[str, Any] = {
            "policy_id": policy_id,
            "policy_version": version,
        }
    elif isinstance(policy, Mapping):
        policy_id = str(policy.get("id", ""))
        version = str(policy.get("version", RECEIPT_VERSION))
        supplied_snapshot = policy.get("snapshot", {})
        if not isinstance(supplied_snapshot, Mapping):
            raise TypeError("policy snapshot must be an object")
        snapshot = {
            **dict(supplied_snapshot),
            "policy_id": policy_id,
            "policy_version": version,
        }
    else:
        raise TypeError("policy must be a policy id or mapping")
    if not policy_id or not version:
        raise ValueError("policy id and version are required")
    _validate_canonical_value(snapshot, "$.policy.snapshot")
    return {
        "id": policy_id,
        "version": version,
        "hash": sha256(snapshot),
        "snapshot": snapshot,
    }


def _legacy_result_mapping(result: Decision) -> tuple[Verdict, Disposition]:
    if result == "green":
        return "VERIFIED", "COMMIT"
    if result == "amber":
        return "UNDECIDABLE", "QUARANTINE"
    if result == "red":
        return "REJECTED", "DENY"
    raise ValueError(f"unsupported legacy result: {result}")


def issue_receipt(
    *,
    run_id: str,
    event_id: str,
    system: str,
    action: str,
    claim: str,
    evidence: Any,
    witness: str,
    signer_key: bytes | Ed25519PrivateKey,
    verdict: Verdict | None = None,
    disposition: Disposition | None = None,
    result: Decision | None = None,
    event_type: str = "boundary_event",
    tokens_used: int = 0,
    next_use_note: str = "Apply receiver policy before downstream use.",
    parent_hash: str | None = None,
    sequence: int = 1,
    policy: str | Mapping[str, Any] = "none",
    control: Mapping[str, Any] | None = None,
    key_id: str | None = None,
    created_at: str | None = None,
) -> Receipt:
    private_key = _coerce_private_key(signer_key)
    if result is not None:
        mapped_verdict, mapped_disposition = _legacy_result_mapping(result)
        if verdict is not None and verdict != mapped_verdict:
            raise ValueError("legacy result conflicts with verdict")
        if disposition is not None and disposition != mapped_disposition:
            raise ValueError("legacy result conflicts with disposition")
        verdict, disposition = mapped_verdict, mapped_disposition
    if verdict is None or disposition is None:
        raise ValueError("verdict and disposition are required")
    public_key = public_key_hex(private_key)
    resolved_key_id = key_id or f"ed25519:{public_key[:24]}"
    control_record = {
        "tool_intent_hash": None,
        "workflow_name": None,
        "workflow_state_hash": None,
        "state_promoted": False,
        **dict(control or {}),
    }
    body = {
        "kind": RECEIPT_KIND,
        "receipt_version": RECEIPT_VERSION,
        "algorithm_id": ALGORITHM_ID,
        "canonicalization_id": CANONICALIZATION_ID,
        "spec_uri": SPEC_URI,
        "wire_canon_uri": WIRE_CANON_URI,
        "attestation": "self",
        "capture_status": "provisional",
        "issuer": {"id": witness, "key_id": resolved_key_id},
        "created_at": created_at or now_iso_utc(),
        "event": {
            "id": event_id,
            "system": system,
            "type": event_type,
            "action": action,
        },
        "claim": claim,
        "evidence": {
            "hash": sha256(evidence),
            "hash_algorithm": "sha256",
            "encoding": "proof-adapter-evidence-json-v1",
        },
        "verdict": verdict,
        "decision": disposition,
        "policy": _policy_record(policy),
        "control": control_record,
        "usage": {"tokens_used": int(tokens_used)},
        "binding": {
            "run_id": run_id,
            "sequence": int(sequence),
            "parent_hash": parent_hash,
        },
        "next_use_note": next_use_note,
        "privacy": {"raw_evidence_stored": False},
    }
    payload_hash = hashlib.sha256(canonical_json(body).encode("ascii")).hexdigest()
    receipt = Receipt(
        payload_hash=payload_hash,
        signature=sign_body(body, private_key),
        **body,
    )
    validate_receipt_profile(receipt)
    return receipt


def _require_fields(value: Mapping[str, Any], expected: set[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise ValueError(f"{field} field mismatch: missing={missing} unknown={unknown}")


def _required_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a nonempty string")


def _hash(value: Any, field: str) -> None:
    if not isinstance(value, str) or not HASH256.fullmatch(value):
        raise ValueError(f"{field} must be lowercase SHA-256 hex")


def validate_receipt_profile(receipt: Receipt | Mapping[str, Any]) -> None:
    data = receipt.to_dict() if isinstance(receipt, Receipt) else dict(receipt)
    _require_fields(data, _TOP_LEVEL_FIELDS, "receipt")
    _validate_canonical_value(data)
    if data["kind"] != RECEIPT_KIND:
        raise UnsupportedReceiptVersion(f"unsupported receipt kind: {data['kind']}")
    if data["receipt_version"] != RECEIPT_VERSION:
        raise UnsupportedReceiptVersion(
            f"unsupported receipt version: {data['receipt_version']}; "
            "preserve historical logs and start a v0.2 log"
        )
    if data["algorithm_id"] != ALGORITHM_ID:
        raise ValueError("algorithm_id mismatch")
    if data["canonicalization_id"] != CANONICALIZATION_ID:
        raise ValueError("canonicalization_id mismatch")
    if data["spec_uri"] != SPEC_URI or data["wire_canon_uri"] != WIRE_CANON_URI:
        raise ValueError("receipt profile URI mismatch")
    if data["attestation"] != "self" or data["capture_status"] != "provisional":
        raise ValueError("proof adapter cannot upgrade its self/provisional trust boundary")

    issuer = data["issuer"]
    event = data["event"]
    evidence = data["evidence"]
    policy = data["policy"]
    control = data["control"]
    usage = data["usage"]
    binding = data["binding"]
    privacy = data["privacy"]
    signature = data["signature"]
    for value, field in (
        (issuer, "issuer"),
        (event, "event"),
        (evidence, "evidence"),
        (policy, "policy"),
        (control, "control"),
        (usage, "usage"),
        (binding, "binding"),
        (privacy, "privacy"),
        (signature, "signature"),
    ):
        if not isinstance(value, Mapping):
            raise ValueError(f"{field} must be an object")

    _require_fields(issuer, {"id", "key_id"}, "issuer")
    _require_fields(event, {"id", "system", "type", "action"}, "event")
    _require_fields(evidence, {"hash", "hash_algorithm", "encoding"}, "evidence")
    _require_fields(policy, {"id", "version", "hash", "snapshot"}, "policy")
    _require_fields(
        control,
        {"tool_intent_hash", "workflow_name", "workflow_state_hash", "state_promoted"},
        "control",
    )
    _require_fields(usage, {"tokens_used"}, "usage")
    _require_fields(binding, {"run_id", "sequence", "parent_hash"}, "binding")
    _require_fields(privacy, {"raw_evidence_stored"}, "privacy")
    _require_fields(signature, {"algorithm", "public_key", "value"}, "signature")

    for field, value in (
        ("issuer.id", issuer["id"]),
        ("issuer.key_id", issuer["key_id"]),
        ("event.id", event["id"]),
        ("event.system", event["system"]),
        ("event.type", event["type"]),
        ("event.action", event["action"]),
        ("claim", data["claim"]),
        ("policy.id", policy["id"]),
        ("policy.version", policy["version"]),
        ("next_use_note", data["next_use_note"]),
    ):
        _required_text(value, field)
    _hash(evidence["hash"], "evidence.hash")
    _hash(policy["hash"], "policy.hash")
    _hash(data["payload_hash"], "payload_hash")
    if evidence["hash_algorithm"] != "sha256":
        raise ValueError("unsupported evidence hash algorithm")
    if evidence["encoding"] != "proof-adapter-evidence-json-v1":
        raise ValueError("unsupported evidence encoding")
    if not isinstance(policy["snapshot"], Mapping):
        raise ValueError("policy.snapshot must be an object")
    if policy["snapshot"].get("policy_id") != policy["id"]:
        raise ValueError("policy snapshot id mismatch")
    if policy["snapshot"].get("policy_version") != policy["version"]:
        raise ValueError("policy snapshot version mismatch")
    expected_policy_hash = sha256(policy["snapshot"])
    if policy["hash"] != expected_policy_hash:
        raise ValueError("policy hash mismatch")
    if data["verdict"] not in {"VERIFIED", "REJECTED", "UNDECIDABLE"}:
        raise ValueError("invalid verdict")
    if data["decision"] not in {
        "COMMIT", "QUARANTINE", "DENY", "NO_BADGE", "ROLLBACK_REQUEST"
    }:
        raise ValueError("invalid disposition")
    if data["verdict"] == "VERIFIED" and data["decision"] != "COMMIT":
        raise ValueError("VERIFIED must map to COMMIT")
    if data["verdict"] == "UNDECIDABLE" and data["decision"] not in {
        "QUARANTINE", "NO_BADGE"
    }:
        raise ValueError("UNDECIDABLE must map to QUARANTINE or NO_BADGE")
    if data["verdict"] == "REJECTED" and data["decision"] == "COMMIT":
        raise ValueError("REJECTED cannot map to COMMIT")
    if control["tool_intent_hash"] is not None:
        _hash(control["tool_intent_hash"], "control.tool_intent_hash")
    workflow_name = control["workflow_name"]
    workflow_hash = control["workflow_state_hash"]
    if (workflow_name is None) != (workflow_hash is None):
        raise ValueError("workflow_name and workflow_state_hash must appear together")
    if workflow_name is not None:
        _required_text(workflow_name, "control.workflow_name")
        _hash(workflow_hash, "control.workflow_state_hash")
    if not isinstance(control["state_promoted"], bool):
        raise ValueError("control.state_promoted must be boolean")
    if control["state_promoted"] and (
        workflow_name is None or data["decision"] != "COMMIT"
    ):
        raise ValueError("only a committed workflow state can be promoted")
    tokens = usage["tokens_used"]
    if not isinstance(tokens, int) or isinstance(tokens, bool) or not 0 <= tokens <= MAX_SAFE_INTEGER:
        raise ValueError("tokens_used must be a nonnegative interoperable integer")
    sequence = binding["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise ValueError("binding.sequence must be a positive integer")
    _required_text(binding["run_id"], "binding.run_id")
    if binding["parent_hash"] is not None:
        _hash(binding["parent_hash"], "binding.parent_hash")
    if privacy["raw_evidence_stored"] is not False:
        raise ValueError("raw evidence must not be stored in this profile")
    try:
        parsed = datetime.fromisoformat(str(data["created_at"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("created_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("created_at must include a timezone")
    if signature["algorithm"] != "Ed25519":
        raise ValueError("unsupported signature algorithm")
    _hash(signature["public_key"], "signature.public_key")
    if not isinstance(signature["value"], str) or not SIGNATURE_HEX.fullmatch(signature["value"]):
        raise ValueError("signature.value must be 64-byte lowercase hex")


def _body_from_data(data: Mapping[str, Any]) -> dict[str, Any]:
    body = dict(data)
    body.pop("payload_hash", None)
    body.pop("signature", None)
    return body


def verify_receipt_integrity(receipt: Receipt | Mapping[str, Any]) -> bool:
    try:
        data = receipt.to_dict() if isinstance(receipt, Receipt) else dict(receipt)
        validate_receipt_profile(data)
        body = _body_from_data(data)
        expected = hashlib.sha256(canonical_json(body).encode("ascii")).hexdigest()
        return data["payload_hash"] == expected
    except (KeyError, TypeError, ValueError):
        return False


def verify_receipt(
    receipt: Receipt | Mapping[str, Any],
    *,
    public_key: str | bytes,
    key_id: str | None = None,
) -> bool:
    try:
        data = receipt.to_dict() if isinstance(receipt, Receipt) else dict(receipt)
        if not verify_receipt_integrity(data):
            return False
        if key_id is not None and data["issuer"]["key_id"] != key_id:
            return False
        body = _body_from_data(data)
        return verify_signature(body, data["signature"], public_key)
    except (KeyError, TypeError, ValueError):
        return False


def _verify_chains(
    receipts: Sequence[Receipt | Mapping[str, Any]],
    receipt_verifier: Any,
) -> bool:
    if not receipts:
        return False
    state: dict[str, tuple[int, str | None, set[str]]] = {}
    for receipt in receipts:
        if not receipt_verifier(receipt):
            return False
        data = receipt.to_dict() if isinstance(receipt, Receipt) else dict(receipt)
        binding = data["binding"]
        event = data["event"]
        run_id = str(binding["run_id"])
        expected_sequence, expected_parent, event_ids = state.get(run_id, (1, None, set()))
        if binding["sequence"] != expected_sequence:
            return False
        if binding["parent_hash"] != expected_parent:
            return False
        event_id = str(event["id"])
        if event_id in event_ids:
            return False
        state[run_id] = (
            expected_sequence + 1,
            str(data["payload_hash"]),
            {*event_ids, event_id},
        )
    return True


def verify_chain_integrity(receipts: Sequence[Receipt | Mapping[str, Any]]) -> bool:
    """Verify every interleaved per-run chain without asserting key authority."""

    return _verify_chains(receipts, verify_receipt_integrity)


def verify_chain(
    receipts: Sequence[Receipt | Mapping[str, Any]],
    *,
    public_key: str | bytes,
    key_id: str | None = None,
) -> bool:
    """Verify an interleaved multi-run log against one externally pinned key."""

    return _verify_chains(
        receipts,
        lambda receipt: verify_receipt(receipt, public_key=public_key, key_id=key_id),
    )


class ReceiptLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, receipt: Receipt) -> None:
        validate_receipt_profile(receipt)
        with self.path.open("a", encoding="ascii") as handle:
            handle.write(canonical_json(receipt.to_dict()) + "\n")

    def load_raw(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        receipts: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    value = strict_json_loads(stripped)
                except (json.JSONDecodeError, DuplicateKeyError, ValueError) as exc:
                    raise ValueError(f"invalid JSON receipt at line {line_number}: {exc}") from exc
                if not isinstance(value, dict):
                    raise ValueError(f"receipt at line {line_number} is not an object")
                receipts.append(value)
        return receipts

    def load(self) -> list[Receipt]:
        receipts: list[Receipt] = []
        for line_number, value in enumerate(self.load_raw(), start=1):
            if value.get("kind") != RECEIPT_KIND or value.get("receipt_version") != RECEIPT_VERSION:
                raise UnsupportedReceiptVersion(
                    f"line {line_number} uses historical profile "
                    f"{value.get('kind')!r}/{value.get('receipt_version')!r}; "
                    "preserve that file and start a new v0.2 log"
                )
            try:
                receipt = Receipt(**value)
                validate_receipt_profile(receipt)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid receipt profile at line {line_number}: {exc}") from exc
            receipts.append(receipt)
        return receipts
