# Migration from 0.1 to 0.2

Version 0.2 is intentionally wire-breaking because the old defaults were not
safe enough to preserve.

## Signing keys

Old:

```python
ProofAdapter(signer_key="shared text secret")
```

New:

```python
ProofAdapter(signer_key_path=".secrets/proof-adapter.key")
```

Use `generate_private_key_file()` once. Text secrets are no longer hashed into
deterministic Ed25519 keys. A caller may instead supply an
`Ed25519PrivateKey` object or exactly 32 raw bytes from an appropriate secret
manager.

## Logs

Do not append v0.2 receipts to a v0.1 file. Preserve the old file as historical
evidence and start a new log. `ReceiptLog.load_raw()` can inspect historical
JSON objects; `ReceiptLog.load()` refuses an old profile so a mixed log cannot
look verified accidentally.

The repository's original sample remains byte-for-byte at
`history/receipts-v0.1.0.jsonl`.

## Decisions

Use `decision.verdict` and `decision.disposition` for new code. The `result`
property maps the new vocabulary to the old color view during migration:

```text
COMMIT      -> green
QUARANTINE  -> amber
other       -> red
```

## Verification

Whole-log verification now treats each `run_id` as an independent chain.
Always supply a public key pinned outside the receipt. Existing code that reads
`receipt.signature["public_key"]` and immediately trusts it must be changed.

