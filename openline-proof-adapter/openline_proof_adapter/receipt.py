"""Receipt primitives for OpenLine Proof Adapter.

Receipts here prove what crossed a boundary and which witness checked it.
They do not prove that the underlying claim is true.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption


Decision = Literal["green", "amber", "red"]


def json_safe(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, dict):
        return {str(key): json_safe(inner) for key, inner in value.items()}
    if isinstance(value, list | tuple):
        return [json_safe(inner) for inner in value]
    if isinstance(value, set | frozenset):
        return [json_safe(inner) for inner in sorted(value, key=repr)]
    return repr(value)


def canonical_json(value: Any) -> str:
    return json.dumps(json_safe(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256(value: str | bytes | Any) -> str:
    if isinstance(value, bytes):
        data = value
    elif isinstance(value, str):
        data = value.encode("utf-8")
    else:
        data = canonical_json(value).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def now_unix_ms() -> int:
    return int(time.time() * 1000)


def _seed_bytes(seed: str | bytes) -> bytes:
    if isinstance(seed, bytes):
        if len(seed) == 32:
            return seed
        return hashlib.sha256(seed).digest()
    try:
        raw = bytes.fromhex(seed)
    except ValueError:
        raw = b""
    if len(raw) == 32:
        return raw
    return hashlib.sha256(seed.encode("utf-8")).digest()


def load_private_key(signer_key: str | bytes | Ed25519PrivateKey) -> Ed25519PrivateKey:
    if isinstance(signer_key, Ed25519PrivateKey):
        return signer_key
    return Ed25519PrivateKey.from_private_bytes(_seed_bytes(signer_key))


def public_key_hex(signer_key: str | bytes | Ed25519PrivateKey) -> str:
    private_key = load_private_key(signer_key)
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def private_key_hex(private_key: Ed25519PrivateKey) -> str:
    return private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()


def sign_body(body: dict[str, Any], signer_key: str | bytes | Ed25519PrivateKey) -> dict[str, str]:
    private_key = load_private_key(signer_key)
    message = canonical_json(body).encode("utf-8")
    return {
        "algorithm": "ed25519",
        "public_key": private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        "value": private_key.sign(message).hex(),
    }


def verify_signature(body: dict[str, Any], signature: dict[str, str], public_key: str | bytes) -> bool:
    if signature.get("algorithm") != "ed25519":
        return False
    expected_public_key = public_key.hex() if isinstance(public_key, bytes) else public_key
    if signature.get("public_key") != expected_public_key:
        return False
    try:
        verifier = Ed25519PublicKey.from_public_bytes(bytes.fromhex(expected_public_key))
        verifier.verify(bytes.fromhex(signature["value"]), canonical_json(body).encode("utf-8"))
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False


@dataclass(frozen=True)
class Receipt:
    kind: str
    receipt_version: str
    run_id: str
    event_id: str
    system: str
    action: str
    claim: str
    evidence_hash: str
    result: Decision
    witness: str
    timestamp_unix_ms: int
    tokens_used: int
    next_use_note: str
    parent_hash: str | None
    policy: str
    key_id: str
    payload_hash: str
    signature: dict[str, str]
    note: str = (
        "This receipt commits what crossed the boundary. With a valid witness "
        "signature, it also attests which configured witness issued it. It does "
        "not prove the underlying claim is true."
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def issue_receipt(
    *,
    run_id: str,
    event_id: str,
    system: str,
    action: str,
    claim: str,
    evidence: Any,
    result: Decision,
    witness: str,
    signer_key: str | bytes | Ed25519PrivateKey,
    tokens_used: int = 0,
    next_use_note: str = "",
    parent_hash: str | None = None,
    policy: str = "none",
    key_id: str = "local-witness",
) -> Receipt:
    body = {
        "kind": "olp_proof_adapter_receipt",
        "receipt_version": "0.1-mvp",
        "run_id": run_id,
        "event_id": event_id,
        "system": system,
        "action": action,
        "claim": claim,
        "evidence_hash": sha256(evidence),
        "result": result,
        "witness": witness,
        "timestamp_unix_ms": now_unix_ms(),
        "tokens_used": int(tokens_used),
        "next_use_note": next_use_note,
        "parent_hash": parent_hash,
        "policy": policy,
        "key_id": key_id,
    }
    return Receipt(payload_hash=sha256(body), signature=sign_body(body, signer_key), **body)


class ReceiptLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, receipt: Receipt) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(receipt.to_dict()) + "\n")

    def load(self) -> list[Receipt]:
        if not self.path.exists():
            return []
        receipts: list[Receipt] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                receipts.append(Receipt(**json.loads(stripped)))
        return receipts


def verify_receipt_integrity(receipt: Receipt | dict[str, Any]) -> bool:
    data = receipt.to_dict() if isinstance(receipt, Receipt) else dict(receipt)
    payload_hash = data.pop("payload_hash")
    data.pop("signature", None)
    data.pop("note", None)
    return sha256(data) == payload_hash


def verify_receipt(receipt: Receipt | dict[str, Any], *, public_key: str | bytes, key_id: str | None = None) -> bool:
    data = receipt.to_dict() if isinstance(receipt, Receipt) else dict(receipt)
    signature = data.pop("signature")
    data.pop("note", None)
    payload_hash = data.pop("payload_hash")
    if key_id is not None and data.get("key_id") != key_id:
        return False
    return sha256(data) == payload_hash and verify_signature(data, signature, public_key)


def verify_chain_integrity(receipts: list[Receipt]) -> bool:
    previous: str | None = None
    for receipt in receipts:
        if not verify_receipt_integrity(receipt):
            return False
        if receipt.parent_hash != previous:
            return False
        previous = receipt.payload_hash
    return True


def verify_chain(receipts: list[Receipt], *, public_key: str | bytes, key_id: str | None = None) -> bool:
    previous: str | None = None
    for receipt in receipts:
        if not verify_receipt(receipt, public_key=public_key, key_id=key_id):
            return False
        if receipt.parent_hash != previous:
            return False
        previous = receipt.payload_hash
    return True
