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
  try {
    const { blake3 } = await import("@noble/hashes/blake3");
    const hash = blake3(data);
    return Array.from(hash).map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch {
    const hash = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
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
  verifyWarrantProofPacket,
  getPublicKey,
  parseLedger
};
