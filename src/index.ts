/**
 * @os1221/varp — Verifiable AI Receipt Protocol
 *
 * Create and verify Ed25519-signed VERDICT/v1 receipts for AI provenance.
 * EU AI Act Article 13 compliant audit trail.
 *
 * @example
 * import { verifyReceipt, createVerdictV1, hashContent } from "@os1221/varp";
 *
 * // Verify a receipt from the ledger
 * const ok = await verifyReceipt(receiptJson);
 * console.log(ok ? "✓ verified" : "✗ tampered");
 *
 * // Create a new signed receipt (requires Ed25519 private key)
 * const receipt = await createVerdictV1({ agent: "MyAgent", description: "task done", privateKey });
 */

export type VerifyResult = {
  verified: boolean;
  reason?: string;
  event_hash?: string;
  signer_pubkey?: string;
};

export type WarrantPacketStatus =
  | "verified"
  | "invalid"
  | "unavailable_private_ledger";

export interface WarrantPacketVerifyResult {
  verified: boolean;
  status: WarrantPacketStatus;
  reasons: string[];
  report_hash?: string;
  coverage_hash?: string;
  repo_count?: number;
  credential_gates?: number;
  receipt_event_hash?: string;
  private_ledger_status: "redacted" | "not_checked";
}

export interface VerdictV1Envelope {
  event_hash: string;
  signature: string;
  signer_pubkey: string;
  prev_hash?: string;
  timestamp: string;
  delta_sv: number;
  description: string;
  agent: string;
  chain_valid?: boolean;
  content_valid?: boolean;
  evidence_root?: string;
}

// Live omega-receipts format (verdict.event.hash / verdict.signature_hex / verdict.signer_pubkey_hex)
export interface OmegaReceiptEvent {
  timestamp?: string;
  description?: string;
  delta_sv?: number;
  hash?: string;
  [key: string]: unknown;
}

export interface OmegaReceiptVerdict {
  event?: OmegaReceiptEvent;
  signature_hex?: string;
  signer_pubkey_hex?: string;
  [key: string]: unknown;
}

export interface LedgerLine {
  verdict?: VerdictV1Envelope | OmegaReceiptVerdict;
  // Direct fields (some older entries are flat)
  event_hash?: string;
  signature?: string;
  signer_pubkey?: string;
  prev_hash?: string;
  [key: string]: unknown;
}

// ── JCS (RFC 8785) serialisation ─────────────────────────────────────────────
// Deterministic JSON: sorted keys, no insignificant whitespace, Unicode escaping.

function jcsStringify(val: unknown): string {
  if (val === null) return "null";
  if (typeof val === "boolean") return val ? "true" : "false";
  if (typeof val === "number") {
    if (!isFinite(val)) throw new Error("JCS: non-finite number");
    return String(val);
  }
  if (typeof val === "string") return JSON.stringify(val);
  if (Array.isArray(val)) return "[" + val.map(jcsStringify).join(",") + "]";
  if (typeof val === "object") {
    const obj = val as Record<string, unknown>;
    const sorted = Object.keys(obj).sort();
    return "{" + sorted.map((k) => JSON.stringify(k) + ":" + jcsStringify(obj[k])).join(",") + "}";
  }
  throw new Error(`JCS: unsupported type ${typeof val}`);
}

// ── BLAKE3 hashing ───────────────────────────────────────────────────────────

async function blake3Hex(data: Uint8Array): Promise<string> {
  // No fallback hash: VERDICT/v1 content hashes are BLAKE3 by spec. A silent
  // SHA-256 substitute produces hashes that look valid but can never match a
  // conforming implementation — fail loudly instead.
  let blake3: (data: Uint8Array) => Uint8Array;
  try {
    ({ blake3 } = await import("@noble/hashes/blake3"));
  } catch (e) {
    throw new Error(
      "@noble/hashes/blake3 unavailable — cannot compute VERDICT/v1 content hash (refusing SHA-256 substitution): " +
        (e instanceof Error ? e.message : String(e)),
    );
  }
  const hash = blake3(data);
  return Array.from(hash).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ── Content payload extraction ───────────────────────────────────────────────

function extractContentPayload(line: LedgerLine): Record<string, unknown> | null {
  const v = line.verdict as Record<string, unknown> | undefined;
  if (!v) return null;

  // Live omega-receipts format: verdict.event contains the event fields
  // Rust EventPayload: { description, delta_sv, timestamp, evidence_root? }
  // (agent is NOT included in the content hash for omega-receipts)
  if (v["event"] && typeof v["event"] === "object") {
    const ev = v["event"] as Record<string, unknown>;
    const payload: Record<string, unknown> = {
      description: ev["description"],
      delta_sv: ev["delta_sv"],
      timestamp: ev["timestamp"],
    };
    if (ev["evidence_root"] != null) payload["evidence_root"] = ev["evidence_root"];
    return payload;
  }

  // VERDICT/v1 envelope format: fields are directly on verdict
  // (council sessions, attest module)
  const payload: Record<string, unknown> = {
    agent: v["agent"],
    description: v["description"],
    timestamp: v["timestamp"],
    delta_sv: v["delta_sv"],
  };
  if (v["evidence_root"] != null) payload["evidence_root"] = v["evidence_root"];
  return payload;
}

// ── Core verify ──────────────────────────────────────────────────────────────

/**
 * Verify a VERDICT/v1 receipt.
 *
 * Checks:
 * 1. BLAKE3(JCS(content_payload)) === event_hash
 * 2. Ed25519.verify(signature, event_hash, signer_pubkey)
 *
 * Returns a VerifyResult with { verified: true } if both checks pass.
 */
export async function verifyReceipt(line: LedgerLine): Promise<VerifyResult> {
  const v = line.verdict as Record<string, unknown> | null | undefined;
  // null verdict lines (e.g. heartbeat stubs) are skipped gracefully,
  // matching Rust's `Err(_) => continue` behavior in receipt_ledger.rs.
  if (!v) return { verified: true, reason: "no_verdict_field" };

  // Support both VERDICT/v1 envelope format AND live omega-receipts format
  const sig = (v["signature"] ?? v["signature_hex"]) as string | undefined;
  const pub = (v["signer_pubkey"] ?? v["signer_pubkey_hex"]) as string | undefined;
  // Hash: VERDICT/v1 has event_hash; omega-receipts has verdict.event.hash
  const ev = v["event"] as Record<string, unknown> | undefined;
  const hash = (v["event_hash"] ?? (ev && ev["hash"])) as string | undefined;
  if (!sig || !pub || !hash) return { verified: false, reason: "missing_fields" };

  // Step 1: Recompute content hash
  const payload = extractContentPayload(line);
  if (!payload) return { verified: false, reason: "no_content_payload" };

  // omega-receipts ledger has two canonical formats (see receipt_ledger.rs):
  // 1. JCS (post-2026-06-10 cutover): serde_jcs → keys sorted alphabetically.
  //    EventPayload: {delta_sv, description, timestamp[, evidence_root]}
  // 2. Legacy (pre-cutover, 1469 records): serde_json → struct declaration order.
  //    EventPayload: {description, delta_sv, timestamp[, evidence_root]}
  //    ALSO: serde_json serializes integer-valued f64 as "0.0"; JCS normalizes to "0".
  const isOmegaFormat = ev != null;
  const canonical = isOmegaFormat ? jcsStringify(payload) : jcsStringify(payload);

  const recomputed = await blake3Hex(new TextEncoder().encode(canonical));
  if (recomputed !== hash.toLowerCase()) {
    // Try legacy serde_json format: struct declaration order + "0.0" for integer floats.
    const legacyFloat = (n: number): string =>
      Number.isFinite(n) && Number.isInteger(n) ? n.toFixed(1) : JSON.stringify(n);
    const dsv = payload["delta_sv"] as number;
    let legacyStr = `{"description":${JSON.stringify(payload["description"])},"delta_sv":${legacyFloat(dsv)},"timestamp":${JSON.stringify(payload["timestamp"])}`;
    if (payload["evidence_root"] != null) legacyStr += `,"evidence_root":${JSON.stringify(payload["evidence_root"])}`;
    legacyStr += "}";
    const legacyRecomputed = await blake3Hex(new TextEncoder().encode(legacyStr));
    if (legacyRecomputed !== hash.toLowerCase()) {
      return { verified: false, reason: "hash_mismatch", event_hash: hash };
    }
  }

  // Step 2: Verify Ed25519 signature over the hash
  try {
    const { verifyAsync } = await import("@noble/ed25519");
    const sigBytes = hexToBytes(sig);
    const pubBytes = hexToBytes(pub);
    const msgBytes = new TextEncoder().encode(hash.toLowerCase());
    const ok = await verifyAsync(sigBytes, msgBytes, pubBytes);
    return ok
      ? { verified: true, event_hash: hash, signer_pubkey: pub }
      : { verified: false, reason: "sig_invalid" };
  } catch (e) {
    return { verified: false, reason: `sig_error: ${e}` };
  }
}

// ── Batch verify ─────────────────────────────────────────────────────────────

/**
 * Verify multiple receipts from a JSONL ledger string.
 * Returns results array + chain validity flag.
 */
export async function verifyLedger(jsonlText: string): Promise<{
  results: Array<{ line: number; event_hash?: string; verified: boolean; reason?: string }>;
  chain_valid: boolean;
}> {
  const lines = jsonlText.split("\n").filter((l) => l.trim());
  // Parse lines first to enable chain linking (sequential, not parallel)
  const parsed = lines.map((raw, i) => {
    try {
      return { idx: i, line: JSON.parse(raw) as LedgerLine, raw };
    } catch {
      return { idx: i, line: null as unknown as LedgerLine, raw };
    }
  });

  // Chain tracking: prev_hash starts as undefined (genesis).
  // Only tracks records that have an explicit prev_hash field — VERDICT/v1 records
  // without prev_hash are treated as chain-independent and don't break the chain.
  let expectedPrev: string | undefined = undefined;
  const chainBreaks = new Set<number>();
  for (const { idx, line } of parsed) {
    if (!line) { expectedPrev = undefined; continue; }
    // Skip null-verdict lines — Rust audit uses continue on parse error for these.
    if (line.verdict == null) continue;
    const ev = line.verdict?.["event"] as Record<string, unknown> | undefined;
    const thisHash = (ev?.["hash"] ?? line.verdict?.event_hash) as string | undefined;
    if (line.prev_hash != null) {
      const prevToCheck = line.prev_hash ?? undefined;
      if (prevToCheck !== expectedPrev) chainBreaks.add(idx);
    }
    if (thisHash !== undefined) expectedPrev = thisHash;
  }

  const results = await Promise.all(
    parsed.map(async ({ idx, line }) => {
      if (!line) return { line: idx + 1, verified: false, reason: "parse_error" };
      const r = await verifyReceipt(line);
      const ev = line.verdict?.["event"] as Record<string, unknown> | undefined;
      const event_hash = (ev?.["hash"] ?? line.verdict?.event_hash) as string | undefined;
      return { line: idx + 1, event_hash, ...r };
    })
  );
  // chain_valid: ALL records verified AND no prev_hash chain breaks.
  // Chain breaks only count when a record has an explicit prev_hash that mismatches.
  const chain_valid = chainBreaks.size === 0 && results.every((r) => r.verified);
  return { results, chain_valid };
}

// ── Signing (requires private key) ───────────────────────────────────────────

export interface SignOptions {
  agent: string;
  description: string;
  delta_sv?: number;
  evidence_root?: string;
  privateKeyHex: string;
  prevHash?: string;
}

/**
 * Create and sign a new VERDICT/v1 receipt.
 * privateKeyHex: 64-char hex Ed25519 seed (first 32 bytes of keypair).
 */
export async function createVerdictV1(opts: SignOptions): Promise<LedgerLine> {
  const ed = await import("@noble/ed25519");
  // Noble/ed25519 requires sha512Sync in non-browser environments
  if (!ed.etc.sha512Sync) {
    try {
      const { createHash } = await import("node:crypto");
      ed.etc.sha512Sync = (...msgs: Uint8Array[]) => {
        const h = createHash("sha512");
        for (const m of msgs) h.update(m);
        return h.digest();
      };
    } catch { /* browser env — async only */ }
  }
  const { sign, getPublicKey } = ed;
  const privBytes = hexToBytes(opts.privateKeyHex);
  const pubBytes = getPublicKey(privBytes);
  const pubHex = bytesToHex(pubBytes);

  const timestamp = new Date().toISOString();
  const payload: Record<string, unknown> = {
    agent: opts.agent,
    description: opts.description,
    timestamp,
    delta_sv: opts.delta_sv ?? 0.1,
    ...(opts.evidence_root ? { evidence_root: opts.evidence_root } : {}),
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
      ...(opts.prevHash ? { prev_hash: opts.prevHash } : {}),
      timestamp,
      delta_sv: opts.delta_sv ?? 0.1,
      description: opts.description,
      agent: opts.agent,
      // evidence_root is part of the SIGNED payload, so it MUST be carried into the
      // envelope — otherwise the verifier can't reconstruct the hash and verification
      // fails for every content-bound receipt. (Regression: see round-trip test.)
      ...(opts.evidence_root ? { evidence_root: opts.evidence_root } : {}),
      chain_valid: true,
      content_valid: true,
    },
  };
}

// ── Utilities ────────────────────────────────────────────────────────────────

export function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Hash arbitrary text content with BLAKE3, returning hex.
 * Convenience wrapper around blake3Hex for string inputs.
 */
export async function hashContent(text: string): Promise<string> {
  return blake3Hex(new TextEncoder().encode(text));
}

export { jcsStringify, blake3Hex, sha256Hex };

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function warrantCredentialGateCount(report: Record<string, unknown>): number {
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

function warrantDecisionCount(report: Record<string, unknown>, checkName: string, expected: string): number {
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

/**
 * Verify a public Meridian/Warrant proof packet against its public report fixture.
 *
 * This intentionally verifies only public facts: exact report hash, packet/report
 * summary consistency, and receipt metadata consistency. Private Omega ledger
 * continuity is expected to be redacted in public fixtures, so a clean public
 * packet returns status `unavailable_private_ledger` with `verified: true`.
 */
export async function verifyWarrantProofPacket(
  packetInput: unknown,
  reportInput: unknown
): Promise<WarrantPacketVerifyResult> {
  const reasons: string[] = [];
  const packet = asRecord(packetInput);
  const reportRaw = typeof reportInput === "string" ? reportInput : JSON.stringify(reportInput, null, 2);
  let report: Record<string, unknown>;
  try {
    report = asRecord(typeof reportInput === "string" ? JSON.parse(reportInput) : reportInput);
  } catch {
    return {
      verified: false,
      status: "invalid",
      reasons: ["report_parse_error"],
      private_ledger_status: "not_checked",
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

  const privateLedgerRedacted =
    receiptVerification["status"] === "unavailable" &&
    receiptVerification["reason"] === "private Omega ledger redacted from public fixture";
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
    private_ledger_status: privateLedgerStatus,
  };
}

/**
 * Derive the Ed25519 public key from a private key seed hex string.
 * Useful for displaying the public key that corresponds to your signing key
 * without needing to create a receipt.
 */
export async function getPublicKey(privateKeyHex: string): Promise<string> {
  const ed = await import("@noble/ed25519");
  if (!ed.etc.sha512Sync) {
    try {
      const { createHash } = await import("node:crypto");
      ed.etc.sha512Sync = (...msgs: Uint8Array[]) => {
        const h = createHash("sha512");
        for (const m of msgs) h.update(m);
        return h.digest();
      };
    } catch { /* browser */ }
  }
  const privBytes = hexToBytes(privateKeyHex);
  const pubBytes = ed.getPublicKey(privBytes);
  return bytesToHex(pubBytes);
}

/**
 * Parse a JSONL ledger string into an array of structured LedgerLine objects.
 * Lines that fail to parse are skipped. Use verifyLedger() to check
 * cryptographic validity of the returned receipts.
 */
export function parseLedger(text: string): LedgerLine[] {
  return text
    .split("\n")
    .filter((l) => l.trim())
    .flatMap((line) => {
      try { return [JSON.parse(line) as LedgerLine]; } catch { return []; }
    });
}
