// src/index.ts
function jcsStringify(val) {
  if (val === null) return "null";
  if (typeof val === "boolean") return val ? "true" : "false";
  if (typeof val === "number") {
    if (!isFinite(val)) throw new Error("JCS: non-finite number");
    return String(val);
  }
  if (typeof val === "string") return JSON.stringify(val);
  if (Array.isArray(val)) return "[" + val.map(jcsStringify).join(",") + "]";
  if (typeof val === "object") {
    const obj = val;
    const sorted = Object.keys(obj).sort();
    return "{" + sorted.map((k) => JSON.stringify(k) + ":" + jcsStringify(obj[k])).join(",") + "}";
  }
  throw new Error(`JCS: unsupported type ${typeof val}`);
}
async function blake3Hex(data) {
  let blake3;
  try {
    ({ blake3 } = await import("@noble/hashes/blake3"));
  } catch (e) {
    throw new Error(
      "@noble/hashes/blake3 unavailable \u2014 cannot compute VERDICT/v1 content hash (refusing SHA-256 substitution): " + (e instanceof Error ? e.message : String(e))
    );
  }
  const hash = blake3(data);
  return Array.from(hash).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sha256Hex(data) {
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function extractContentPayload(line) {
  const v = line.verdict;
  if (!v) return null;
  if (v["event"] && typeof v["event"] === "object") {
    const ev = v["event"];
    const payload2 = {
      description: ev["description"],
      delta_sv: ev["delta_sv"],
      timestamp: ev["timestamp"]
    };
    if (ev["evidence_root"] != null) payload2["evidence_root"] = ev["evidence_root"];
    return payload2;
  }
  const payload = {
    agent: v["agent"],
    description: v["description"],
    timestamp: v["timestamp"],
    delta_sv: v["delta_sv"]
  };
  if (v["evidence_root"] != null) payload["evidence_root"] = v["evidence_root"];
  return payload;
}
async function verifyReceipt(line) {
  const v = line.verdict;
  if (!v) return { verified: true, reason: "no_verdict_field" };
  const sig = v["signature"] ?? v["signature_hex"];
  const pub = v["signer_pubkey"] ?? v["signer_pubkey_hex"];
  const ev = v["event"];
  const hash = v["event_hash"] ?? (ev && ev["hash"]);
  if (!sig || !pub || !hash) return { verified: false, reason: "missing_fields" };
  const payload = extractContentPayload(line);
  if (!payload) return { verified: false, reason: "no_content_payload" };
  const isOmegaFormat = ev != null;
  const canonical = isOmegaFormat ? jcsStringify(payload) : jcsStringify(payload);
  const recomputed = await blake3Hex(new TextEncoder().encode(canonical));
  if (recomputed !== hash.toLowerCase()) {
    const legacyFloat = (n) => Number.isFinite(n) && Number.isInteger(n) ? n.toFixed(1) : JSON.stringify(n);
    const dsv = payload["delta_sv"];
    let legacyStr = `{"description":${JSON.stringify(payload["description"])},"delta_sv":${legacyFloat(dsv)},"timestamp":${JSON.stringify(payload["timestamp"])}`;
    if (payload["evidence_root"] != null) legacyStr += `,"evidence_root":${JSON.stringify(payload["evidence_root"])}`;
    legacyStr += "}";
    const legacyRecomputed = await blake3Hex(new TextEncoder().encode(legacyStr));
    if (legacyRecomputed !== hash.toLowerCase()) {
      return { verified: false, reason: "hash_mismatch", event_hash: hash };
    }
  }
  try {
    const { verifyAsync } = await import("@noble/ed25519");
    const sigBytes = hexToBytes(sig);
    const pubBytes = hexToBytes(pub);
    const msgBytes = new TextEncoder().encode(hash.toLowerCase());
    const ok = await verifyAsync(sigBytes, msgBytes, pubBytes);
    return ok ? { verified: true, event_hash: hash, signer_pubkey: pub } : { verified: false, reason: "sig_invalid" };
  } catch (e) {
    return { verified: false, reason: `sig_error: ${e}` };
  }
}
async function verifyLedger(jsonlText) {
  const lines = jsonlText.split("\n").filter((l) => l.trim());
  const parsed = lines.map((raw, i) => {
    try {
      return { idx: i, line: JSON.parse(raw), raw };
    } catch {
      return { idx: i, line: null, raw };
    }
  });
  let expectedPrev = void 0;
  const chainBreaks = /* @__PURE__ */ new Set();
  for (const { idx, line } of parsed) {
    if (!line) {
      expectedPrev = void 0;
      continue;
    }
    if (line.verdict == null) continue;
    const ev = line.verdict?.["event"];
    const thisHash = ev?.["hash"] ?? line.verdict?.event_hash;
    if (line.prev_hash != null) {
      const prevToCheck = line.prev_hash ?? void 0;
      if (prevToCheck !== expectedPrev) chainBreaks.add(idx);
    }
    if (thisHash !== void 0) expectedPrev = thisHash;
  }
  const results = await Promise.all(
    parsed.map(async ({ idx, line }) => {
      if (!line) return { line: idx + 1, verified: false, reason: "parse_error" };
      const r = await verifyReceipt(line);
      const ev = line.verdict?.["event"];
      const event_hash = ev?.["hash"] ?? line.verdict?.event_hash;
      return { line: idx + 1, event_hash, ...r };
    })
  );
  const chain_valid = chainBreaks.size === 0 && results.every((r) => r.verified);
  return { results, chain_valid };
}
async function createVerdictV1(opts) {
  const ed = await import("@noble/ed25519");
  if (!ed.etc.sha512Sync) {
    try {
      const { createHash } = await import("crypto");
      ed.etc.sha512Sync = (...msgs) => {
        const h = createHash("sha512");
        for (const m of msgs) h.update(m);
        return h.digest();
      };
    } catch {
    }
  }
  const { sign, getPublicKey: getPublicKey2 } = ed;
  const privBytes = hexToBytes(opts.privateKeyHex);
  const pubBytes = getPublicKey2(privBytes);
  const pubHex = bytesToHex(pubBytes);
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  const payload = {
    agent: opts.agent,
    description: opts.description,
    timestamp,
    delta_sv: opts.delta_sv ?? 0.1,
    ...opts.evidence_root ? { evidence_root: opts.evidence_root } : {}
  };
  const canonical = jcsStringify(payload);
  const event_hash = await blake3Hex(new TextEncoder().encode(canonical));
  const sigBytes = await sign(new TextEncoder().encode(event_hash), privBytes);
  const signature = bytesToHex(sigBytes);
  return {
    verdict: {
      event_hash,
      signature,
      signer_pubkey: pubHex,
      ...opts.prevHash ? { prev_hash: opts.prevHash } : {},
      timestamp,
      delta_sv: opts.delta_sv ?? 0.1,
      description: opts.description,
      agent: opts.agent,
      // evidence_root is part of the SIGNED payload, so it MUST be carried into the
      // envelope — otherwise the verifier can't reconstruct the hash and verification
      // fails for every content-bound receipt. (Regression: see round-trip test.)
      ...opts.evidence_root ? { evidence_root: opts.evidence_root } : {},
      chain_valid: true,
      content_valid: true
    }
  };
}
function hexToBytes(hex) {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function hashContent(text) {
  return blake3Hex(new TextEncoder().encode(text));
}
async function ed25519Verify(signatureHex, message, publicKeyHex) {
  const { verifyAsync } = await import("@noble/ed25519");
  const msgBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
  try {
    return await verifyAsync(hexToBytes(signatureHex), msgBytes, hexToBytes(publicKeyHex));
  } catch {
    return false;
  }
}
function asRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}
function numberValue(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : void 0;
}
function stringValue(value) {
  return typeof value === "string" ? value : void 0;
}
function warrantCredentialGateCount(report) {
  const repos = Array.isArray(report["repos"]) ? report["repos"] : [];
  let count = 0;
  for (const rawRepo of repos) {
    const repo = asRecord(rawRepo);
    const checks = asRecord(repo["checks"]);
    const credential = asRecord(checks["credential_requires_approval"]);
    const decision = credential["decision"];
    if (decision === "require_approval" || decision === "block") count++;
  }
  return count;
}
function warrantDecisionCount(report, checkName, expected) {
  const repos = Array.isArray(report["repos"]) ? report["repos"] : [];
  let count = 0;
  for (const rawRepo of repos) {
    const repo = asRecord(rawRepo);
    const checks = asRecord(repo["checks"]);
    const check = asRecord(checks[checkName]);
    if (check["decision"] === expected) count++;
  }
  return count;
}
async function verifyWarrantProofPacket(packetInput, reportInput) {
  const reasons = [];
  const packet = asRecord(packetInput);
  const reportRaw = typeof reportInput === "string" ? reportInput : JSON.stringify(reportInput, null, 2);
  let report;
  try {
    report = asRecord(typeof reportInput === "string" ? JSON.parse(reportInput) : reportInput);
  } catch {
    return {
      verified: false,
      status: "invalid",
      reasons: ["report_parse_error"],
      private_ledger_status: "not_checked"
    };
  }
  if (packet["schema"] !== "meridian-warrant-proof-packet/0.1") {
    reasons.push("packet_schema_mismatch");
  }
  if (packet["status"] !== "pass") reasons.push("packet_status_not_pass");
  const reportSection = asRecord(packet["report"]);
  const preflight = asRecord(packet["preflight"]);
  const receipt = asRecord(packet["receipt"]);
  const receiptVerification = asRecord(receipt["verification"]);
  const reportHash = "sha256:" + await sha256Hex(new TextEncoder().encode(reportRaw));
  if (reportSection["evidenceHash"] !== reportHash) reasons.push("report_hash_mismatch");
  const repos = Array.isArray(report["repos"]) ? report["repos"] : [];
  const repoCount = repos.length;
  const policyGenerated = repos.filter((repo) => asRecord(repo)["policy_generated"] === true).length;
  const summary = asRecord(report["summary"]);
  const failures = Array.isArray(summary["failures"]) ? summary["failures"].length : 0;
  const coverageHash = stringValue(report["coverage_hash"]);
  const destructiveBlocks = warrantDecisionCount(report, "builtin_destructive_block", "block");
  const readOnlyAllows = warrantDecisionCount(report, "read_only_allows", "allow");
  const credentialGates = warrantCredentialGateCount(report);
  if (numberValue(reportSection["repoCount"]) !== repoCount) reasons.push("repo_count_mismatch");
  if (numberValue(reportSection["policyGenerated"]) !== policyGenerated) reasons.push("policy_generated_mismatch");
  if (numberValue(reportSection["failures"]) !== failures) reasons.push("failure_count_mismatch");
  if (reportSection["coverageHash"] !== coverageHash) reasons.push("coverage_hash_mismatch");
  if (numberValue(preflight["destructiveBlocks"]) !== destructiveBlocks) reasons.push("destructive_blocks_mismatch");
  if (numberValue(preflight["readOnlyAllows"]) !== readOnlyAllows) reasons.push("read_only_allows_mismatch");
  if (numberValue(preflight["credentialGates"]) !== credentialGates) reasons.push("credential_gates_mismatch");
  const reportReceipt = asRecord(report["receipt"]);
  const receiptEventHash = stringValue(reportReceipt["event_hash"]);
  const receiptCoverageHash = stringValue(reportReceipt["coverage_hash"]);
  if (receipt["status"] !== "signed") reasons.push("receipt_not_signed");
  if (receipt["eventHash"] !== receiptEventHash) reasons.push("receipt_event_hash_mismatch");
  if (receipt["coverageHash"] !== receiptCoverageHash || receipt["coverageHash"] !== coverageHash) {
    reasons.push("receipt_coverage_hash_mismatch");
  }
  const privateLedgerRedacted = receiptVerification["status"] === "unavailable" && receiptVerification["reason"] === "private Omega ledger redacted from public fixture";
  const privateLedgerStatus = privateLedgerRedacted ? "redacted" : "not_checked";
  if (!privateLedgerRedacted) reasons.push("private_ledger_status_not_redacted");
  const verified = reasons.length === 0;
  return {
    verified,
    status: verified ? "unavailable_private_ledger" : "invalid",
    reasons: verified ? ["public_packet_verified_private_ledger_redacted"] : reasons,
    report_hash: reportHash,
    coverage_hash: coverageHash,
    repo_count: repoCount,
    credential_gates: credentialGates,
    receipt_event_hash: receiptEventHash,
    private_ledger_status: privateLedgerStatus
  };
}
var PROOF_PACKET_SCHEMA = "verdict.proof-packet/v1";
var SHA256_HEX_RE = /^[0-9a-f]{64}$/;
function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function nonEmptyString(value) {
  return typeof value === "string" && value.trim() !== "";
}
function decimalValue(value) {
  if (value === null || value === void 0 || value === "") return void 0;
  if (typeof value !== "number" && typeof value !== "string") return void 0;
  const n = Number(value);
  return Number.isFinite(n) ? n : void 0;
}
async function validateProofPacketClaim(claim, errors) {
  const statement = claim["statement"];
  const statementSha256 = claim["statement_sha256"];
  if (!statement && !statementSha256) {
    errors.push("claim must include statement or statement_sha256");
    return;
  }
  if (statement !== void 0 && statement !== null && typeof statement !== "string") {
    errors.push("claim.statement must be a string");
    return;
  }
  if (statementSha256 !== void 0 && statementSha256 !== null && (typeof statementSha256 !== "string" || !SHA256_HEX_RE.test(statementSha256))) {
    errors.push("claim.statement_sha256 must be 64 lowercase hex chars");
    return;
  }
  if (statement && statementSha256) {
    const recomputed = await sha256Hex(new TextEncoder().encode(statement));
    if (recomputed !== statementSha256) {
      errors.push("claim.statement_sha256 does not match claim.statement");
    }
  }
}
async function validateProofPacket(packetInput) {
  if (!isPlainObject(packetInput)) {
    return { valid: false, errors: ["packet must be an object"] };
  }
  const packet = packetInput;
  const errors = [];
  if (packet["schema"] !== PROOF_PACKET_SCHEMA) {
    errors.push(`schema must be ${PROOF_PACKET_SCHEMA}`);
  }
  for (const field of ["issued_at", "producer", "subject", "action"]) {
    if (!nonEmptyString(packet[field])) errors.push(`${field} must be a non-empty string`);
  }
  const unit = packet["unit"];
  if (!isPlainObject(unit)) {
    errors.push("unit must be an object");
  } else {
    for (const field of ["id", "unit", "currency"]) {
      if (!nonEmptyString(unit[field])) errors.push(`unit.${field} must be a non-empty string`);
    }
    const amount = decimalValue(unit["amount_usd"]);
    const maxAmount = decimalValue(unit["max_amount_usd"]);
    if (amount !== void 0 && amount < 0) errors.push("unit.amount_usd must be non-negative");
    if (maxAmount !== void 0 && maxAmount < 0) {
      errors.push("unit.max_amount_usd must be non-negative");
    }
    if (amount !== void 0 && maxAmount !== void 0 && amount > maxAmount) {
      errors.push("unit.amount_usd must not exceed unit.max_amount_usd");
    }
  }
  const claim = packet["claim"];
  if (!isPlainObject(claim)) {
    errors.push("claim must be an object");
  } else {
    await validateProofPacketClaim(claim, errors);
  }
  const evidence = packet["evidence"];
  if (!Array.isArray(evidence)) {
    errors.push("evidence must be a list");
  } else {
    evidence.forEach((item, index) => {
      if (!isPlainObject(item)) {
        errors.push(`evidence[${index}] must be an object`);
        return;
      }
      if (!nonEmptyString(item["type"])) {
        errors.push(`evidence[${index}].type must be a non-empty string`);
      }
      const hasRef = ["uri", "content_sha256", "content_hash", "chain_hash"].some(
        (f) => Boolean(item[f])
      );
      if (!hasRef) {
        errors.push(
          `evidence[${index}] must include uri, content_sha256, content_hash, or chain_hash`
        );
      }
    });
  }
  const receipts = packet["receipts"];
  if (!Array.isArray(receipts)) {
    errors.push("receipts must be a list");
  } else {
    receipts.forEach((item, index) => {
      if (!isPlainObject(item)) {
        errors.push(`receipts[${index}] must be an object`);
        return;
      }
      if (!nonEmptyString(item["protocol"])) {
        errors.push(`receipts[${index}].protocol must be a non-empty string`);
      }
      const hasRef = [
        "content_hash",
        "chain_hash",
        "receipt_sha256",
        "envelope_sha256",
        "signature"
      ].some((f) => Boolean(item[f]));
      if (!hasRef) {
        errors.push(
          `receipts[${index}] must include content_hash, chain_hash, receipt_sha256, envelope_sha256, or signature`
        );
      }
    });
  }
  const payment = packet["payment"];
  if (payment !== void 0 && payment !== null) {
    if (!isPlainObject(payment)) {
      errors.push("payment must be an object when present");
    } else if (isPlainObject(unit)) {
      const amount = decimalValue(payment["amount_usd"]);
      const maxAmount = decimalValue(unit["max_amount_usd"]);
      if (amount !== void 0 && amount < 0) {
        errors.push("payment.amount_usd must be non-negative");
      }
      if (amount !== void 0 && maxAmount !== void 0 && amount > maxAmount) {
        errors.push("payment.amount_usd must not exceed unit.max_amount_usd");
      }
    }
  }
  return { valid: errors.length === 0, errors };
}
function extractProofPacketArtifact(payload) {
  const p = asRecord(payload);
  if (isPlainObject(p["packet"])) return ["proof_packet", p["packet"]];
  if (isPlainObject(p["envelope"])) return ["verdict_v1_envelope", p["envelope"]];
  if (p["schema"] === PROOF_PACKET_SCHEMA) return ["proof_packet", payload];
  if (p["protocol"] === "VERDICT/v1") return ["verdict_v1_envelope", payload];
  throw new Error(
    "input must be a proof packet, a VERDICT/v1 envelope, or include packet/envelope"
  );
}
function proofPacketUnitId(packet) {
  const unit = packet["unit"];
  return isPlainObject(unit) ? stringValue(unit["id"]) : void 0;
}
async function verifyV1EnvelopeSignature(envelope) {
  const receipt = envelope["receipt"];
  const claimed = envelope["content_hash"];
  const sig = envelope["signature"];
  const pub = envelope["signer_pubkey"];
  if (!isPlainObject(receipt) || typeof claimed !== "string" || typeof sig !== "string" || typeof pub !== "string") {
    return false;
  }
  try {
    const recomputed = await blake3Hex(new TextEncoder().encode(jcsStringify(receipt)));
    if (recomputed !== claimed) return false;
    const { verifyAsync } = await import("@noble/ed25519");
    return await verifyAsync(
      hexToBytes(sig),
      new TextEncoder().encode(claimed),
      hexToBytes(pub)
    );
  } catch {
    return false;
  }
}
async function verifyProofPacket(input) {
  const [kind, artifact] = extractProofPacketArtifact(input);
  if (kind === "proof_packet") {
    const validation2 = await validateProofPacket(artifact);
    const packet2 = asRecord(artifact);
    return {
      kind,
      valid: validation2.valid,
      signature_valid: null,
      validation: validation2,
      errors: [...validation2.errors],
      subject: stringValue(packet2["subject"]),
      action: stringValue(packet2["action"]),
      unit_id: proofPacketUnitId(packet2)
    };
  }
  const envelope = asRecord(artifact);
  const receipt = envelope["receipt"];
  const validation = await validateProofPacket(receipt);
  const errors = [...validation.errors];
  if (envelope["protocol"] !== "VERDICT/v1") {
    errors.push("envelope.protocol must be VERDICT/v1");
  }
  const signatureValid = await verifyV1EnvelopeSignature(envelope);
  if (!signatureValid) errors.push("signature_invalid");
  const packet = asRecord(receipt);
  return {
    kind,
    // Derived from the full error list so it can never disagree with errors.
    valid: errors.length === 0,
    signature_valid: signatureValid,
    validation,
    errors,
    subject: stringValue(packet["subject"]),
    action: stringValue(packet["action"]),
    unit_id: proofPacketUnitId(packet),
    content_hash: stringValue(envelope["content_hash"]),
    signer_pubkey: stringValue(envelope["signer_pubkey"])
  };
}
async function getPublicKey(privateKeyHex) {
  const ed = await import("@noble/ed25519");
  if (!ed.etc.sha512Sync) {
    try {
      const { createHash } = await import("crypto");
      ed.etc.sha512Sync = (...msgs) => {
        const h = createHash("sha512");
        for (const m of msgs) h.update(m);
        return h.digest();
      };
    } catch {
    }
  }
  const privBytes = hexToBytes(privateKeyHex);
  const pubBytes = ed.getPublicKey(privBytes);
  return bytesToHex(pubBytes);
}
function parseLedger(text) {
  return text.split("\n").filter((l) => l.trim()).flatMap((line) => {
    try {
      return [JSON.parse(line)];
    } catch {
      return [];
    }
  });
}

export {
  jcsStringify,
  blake3Hex,
  sha256Hex,
  verifyReceipt,
  verifyLedger,
  createVerdictV1,
  hexToBytes,
  bytesToHex,
  hashContent,
  ed25519Verify,
  verifyWarrantProofPacket,
  PROOF_PACKET_SCHEMA,
  validateProofPacket,
  verifyProofPacket,
  getPublicKey,
  parseLedger
};
