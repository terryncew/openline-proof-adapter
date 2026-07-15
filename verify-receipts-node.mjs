#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import process from "node:process";

const TOP_LEVEL_FIELDS = [
  "algorithm_id", "attestation", "binding", "canonicalization_id",
  "capture_status", "claim", "control", "created_at", "decision", "event",
  "evidence", "issuer", "kind", "next_use_note", "payload_hash", "policy",
  "privacy", "receipt_version", "signature", "spec_uri", "usage",
  "verdict", "wire_canon_uri",
];
const HASH = /^[0-9a-f]{64}$/;
const SIGNATURE = /^[0-9a-f]{128}$/;

function strictParse(text) {
  let position = 0;
  const whitespace = () => {
    while (/\s/.test(text[position] ?? "")) position += 1;
  };
  const value = () => {
    whitespace();
    const char = text[position];
    if (char === "{") return object();
    if (char === "[") return array();
    if (char === '"') return string();
    for (const [literal, result] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(literal, position)) {
        position += literal.length;
        return result;
      }
    }
    const match = text.slice(position).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (!match) throw new Error(`invalid JSON value at byte ${position}`);
    position += match[0].length;
    return Number(match[0]);
  };
  const string = () => {
    const start = position;
    position += 1;
    let escaped = false;
    while (position < text.length) {
      const char = text[position++];
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === '"') {
        return JSON.parse(text.slice(start, position));
      } else if (char.charCodeAt(0) < 0x20) {
        throw new Error(`unescaped control character at byte ${position - 1}`);
      }
    }
    throw new Error("unterminated JSON string");
  };
  const array = () => {
    const result = [];
    position += 1;
    whitespace();
    if (text[position] === "]") {
      position += 1;
      return result;
    }
    while (true) {
      result.push(value());
      whitespace();
      const char = text[position++];
      if (char === "]") return result;
      if (char !== ",") throw new Error(`expected array separator at byte ${position - 1}`);
    }
  };
  const object = () => {
    const result = {};
    const keys = new Set();
    position += 1;
    whitespace();
    if (text[position] === "}") {
      position += 1;
      return result;
    }
    while (true) {
      whitespace();
      if (text[position] !== '"') throw new Error(`expected object key at byte ${position}`);
      const key = string();
      if (keys.has(key)) throw new Error(`duplicate JSON key: ${key}`);
      keys.add(key);
      whitespace();
      if (text[position++] !== ":") throw new Error(`expected colon at byte ${position - 1}`);
      result[key] = value();
      whitespace();
      const char = text[position++];
      if (char === "}") return result;
      if (char !== ",") throw new Error(`expected object separator at byte ${position - 1}`);
    }
  };
  const result = value();
  whitespace();
  if (position !== text.length) throw new Error(`trailing JSON content at byte ${position}`);
  return result;
}

function quoteAscii(value) {
  return JSON.stringify(value).replace(/[\u0080-\uffff]/g, (char) =>
    `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`
  );
}

function canonical(value, path = "$") {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error(`${path}: non-interoperable number`);
    return String(value);
  }
  if (typeof value === "string") return quoteAscii(value);
  if (Array.isArray(value)) {
    return `[${value.map((item, index) => canonical(item, `${path}[${index}]`)).join(",")}]`;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value);
    for (const key of keys) {
      if (!/^[\x00-\x7f]*$/.test(key)) throw new Error(`${path}: non-ASCII object key`);
    }
    keys.sort();
    return `{${keys.map((key) => `${quoteAscii(key)}:${canonical(value[key], `${path}.${key}`)}`).join(",")}}`;
  }
  throw new Error(`${path}: unsupported value`);
}

function exactFields(value, expected, field) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${field}_not_object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) throw new Error(`${field}_field_mismatch`);
}

function requiredText(value, field) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${field}_invalid`);
}

function validateProfile(receipt) {
  exactFields(receipt, TOP_LEVEL_FIELDS, "receipt");
  if (receipt.kind !== "proof_adapter_boundary_assessment_receipt") throw new Error("kind_unsupported");
  if (receipt.receipt_version !== "0.2") throw new Error("version_unsupported");
  if (receipt.algorithm_id !== "openline-proof-adapter-boundary-0.2") throw new Error("algorithm_unsupported");
  if (receipt.canonicalization_id !== "olp-canonical-json-int-v1") throw new Error("canonicalization_unsupported");
  if (receipt.attestation !== "self" || receipt.capture_status !== "provisional") throw new Error("trust_profile_invalid");
  exactFields(receipt.issuer, ["id", "key_id"], "issuer");
  exactFields(receipt.event, ["action", "id", "system", "type"], "event");
  exactFields(receipt.evidence, ["encoding", "hash", "hash_algorithm"], "evidence");
  exactFields(receipt.policy, ["hash", "id", "snapshot", "version"], "policy");
  exactFields(receipt.control, ["state_promoted", "tool_intent_hash", "workflow_name", "workflow_state_hash"], "control");
  exactFields(receipt.usage, ["tokens_used"], "usage");
  exactFields(receipt.binding, ["parent_hash", "run_id", "sequence"], "binding");
  exactFields(receipt.privacy, ["raw_evidence_stored"], "privacy");
  exactFields(receipt.signature, ["algorithm", "public_key", "value"], "signature");
  for (const [field, value] of [
    ["issuer_id", receipt.issuer.id], ["issuer_key_id", receipt.issuer.key_id],
    ["event_id", receipt.event.id], ["event_system", receipt.event.system],
    ["event_type", receipt.event.type], ["event_action", receipt.event.action],
    ["claim", receipt.claim], ["policy_id", receipt.policy.id],
    ["policy_version", receipt.policy.version], ["run_id", receipt.binding.run_id],
    ["next_use_note", receipt.next_use_note],
  ]) requiredText(value, field);
  if (!HASH.test(receipt.evidence.hash) || receipt.evidence.hash_algorithm !== "sha256") throw new Error("evidence_invalid");
  if (receipt.evidence.encoding !== "proof-adapter-evidence-json-v1") throw new Error("evidence_encoding_invalid");
  if (!HASH.test(receipt.policy.hash) || !HASH.test(receipt.payload_hash)) throw new Error("hash_invalid");
  exactFields(receipt.policy.snapshot, [
    ...Object.keys(receipt.policy.snapshot),
  ], "policy_snapshot");
  if (receipt.policy.snapshot.policy_id !== receipt.policy.id) throw new Error("policy_snapshot_id_mismatch");
  if (receipt.policy.snapshot.policy_version !== receipt.policy.version) throw new Error("policy_snapshot_version_mismatch");
  const policyHash = crypto.createHash("sha256").update(canonical(receipt.policy.snapshot), "ascii").digest("hex");
  if (receipt.policy.hash !== policyHash) throw new Error("policy_hash_mismatch");
  if (!["VERIFIED", "REJECTED", "UNDECIDABLE"].includes(receipt.verdict)) throw new Error("verdict_invalid");
  if (!["COMMIT", "QUARANTINE", "DENY", "NO_BADGE", "ROLLBACK_REQUEST"].includes(receipt.decision)) throw new Error("decision_invalid");
  if (receipt.verdict === "VERIFIED" && receipt.decision !== "COMMIT") throw new Error("verified_mapping_invalid");
  if (receipt.verdict === "UNDECIDABLE" && !["QUARANTINE", "NO_BADGE"].includes(receipt.decision)) throw new Error("undecidable_mapping_invalid");
  if (receipt.verdict === "REJECTED" && receipt.decision === "COMMIT") throw new Error("rejected_mapping_invalid");
  if (!Number.isSafeInteger(receipt.usage.tokens_used) || receipt.usage.tokens_used < 0) throw new Error("tokens_invalid");
  if (!Number.isSafeInteger(receipt.binding.sequence) || receipt.binding.sequence < 1) throw new Error("sequence_invalid");
  if (receipt.binding.parent_hash !== null && !HASH.test(receipt.binding.parent_hash)) throw new Error("parent_hash_invalid");
  for (const field of ["tool_intent_hash", "workflow_state_hash"]) {
    if (receipt.control[field] !== null && !HASH.test(receipt.control[field])) throw new Error(`${field}_invalid`);
  }
  if ((receipt.control.workflow_name === null) !== (receipt.control.workflow_state_hash === null)) throw new Error("workflow_control_incomplete");
  if (typeof receipt.control.state_promoted !== "boolean") throw new Error("state_promoted_invalid");
  if (receipt.control.state_promoted && (receipt.control.workflow_name === null || receipt.decision !== "COMMIT")) throw new Error("state_promotion_invalid");
  if (receipt.privacy.raw_evidence_stored !== false) throw new Error("privacy_profile_invalid");
  if (receipt.signature.algorithm !== "Ed25519" || !HASH.test(receipt.signature.public_key) || !SIGNATURE.test(receipt.signature.value)) throw new Error("signature_shape_invalid");
  if (Number.isNaN(Date.parse(receipt.created_at))) throw new Error("created_at_invalid");
  canonical(receipt);
}

function verifyReceipt(receipt, trustedKey) {
  validateProfile(receipt);
  if (receipt.signature.public_key !== trustedKey) throw new Error("signer_key_not_trusted");
  const body = {...receipt};
  delete body.payload_hash;
  delete body.signature;
  const encoded = Buffer.from(canonical(body), "ascii");
  const payloadHash = crypto.createHash("sha256").update(encoded).digest("hex");
  if (payloadHash !== receipt.payload_hash) throw new Error("payload_hash_mismatch");
  const publicDer = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(trustedKey, "hex"),
  ]);
  const publicKey = crypto.createPublicKey({key: publicDer, format: "der", type: "spki"});
  if (!crypto.verify(null, encoded, publicKey, Buffer.from(receipt.signature.value, "hex"))) {
    throw new Error("signature_invalid");
  }
}

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

const path = process.argv[2];
const trustedKey = (argument("--trusted-key") ?? "").replace(/^ed25519:/, "");
if (!path || !HASH.test(trustedKey)) {
  process.stderr.write("usage: node verify-receipts-node.mjs RECEIPTS.jsonl --trusted-key HEX\n");
  process.exit(2);
}

const lines = fs.readFileSync(path, "utf8").split(/\r?\n/).filter((line) => line.trim());
const errors = [];
const receipts = [];
for (const [index, line] of lines.entries()) {
  try {
    const receipt = strictParse(line);
    verifyReceipt(receipt, trustedKey);
    receipts.push(receipt);
  } catch (error) {
    errors.push(`line_${index + 1}:${error.message}`);
  }
}

const chains = new Map();
for (const [index, receipt] of receipts.entries()) {
  const runId = receipt.binding.run_id;
  const state = chains.get(runId) ?? {sequence: 1, parent: null, eventIds: new Set()};
  if (receipt.binding.sequence !== state.sequence) errors.push(`line_${index + 1}:sequence_mismatch`);
  if (receipt.binding.parent_hash !== state.parent) errors.push(`line_${index + 1}:parent_hash_mismatch`);
  if (state.eventIds.has(receipt.event.id)) errors.push(`line_${index + 1}:duplicate_event_id`);
  state.eventIds.add(receipt.event.id);
  state.sequence += 1;
  state.parent = receipt.payload_hash;
  chains.set(runId, state);
}
if (receipts.length === 0) errors.push("receipt_log_empty");

const report = {
  schema: "openline.proof_adapter.node_verification.v0.2",
  valid: errors.length === 0,
  count: receipts.length,
  run_count: chains.size,
  errors: [...new Set(errors)].sort(),
  last_hashes: Object.fromEntries([...chains.entries()].map(([runId, state]) => [runId, state.parent])),
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (!report.valid) process.exitCode = 1;
