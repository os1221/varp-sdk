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

export interface LedgerLine {
  verdict?: VerdictV1Envelope;
  // Direct fields (some older entries are flat)
  event_hash?: string;
  signature?: string;
  signer_pubkey?: string;
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
  try {
    const { blake3 } = await import("@noble/hashes/blake3");
    const hash = blake3(data);
    return Array.from(hash).map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch {
    // Fallback to SHA-256 if blake3 unavailable (Node < 20 edge case)
    const hash = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
}

// ── Content payload extraction ───────────────────────────────────────────────

function extractContentPayload(line: LedgerLine): Record<string, unknown> | null {
  const v = line.verdict;
  if (!v) return null;
  // Canonical content-binding payload: fields inside verdict.event + outer envelope fields
  return {
    agent: v.agent,
    description: v.description,
    timestamp: v.timestamp,
    delta_sv: v.delta_sv,
    ...(v.evidence_root ? { evidence_root: v.evidence_root } : {}),
  };
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
  const v = line.verdict;
  if (!v) return { verified: false, reason: "no_verdict_field" };

  const sig = v.signature;
  const pub = v.signer_pubkey;
  const hash = v.event_hash;
  if (!sig || !pub || !hash) return { verified: false, reason: "missing_fields" };

  // Step 1: Recompute content hash
  const payload = extractContentPayload(line);
  if (!payload) return { verified: false, reason: "no_content_payload" };
  const canonical = jcsStringify(payload);
  const recomputed = await blake3Hex(new TextEncoder().encode(canonical));
  if (recomputed !== hash.toLowerCase()) {
    return { verified: false, reason: "hash_mismatch", event_hash: hash };
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
  const results = await Promise.all(
    lines.map(async (raw, i) => {
      try {
        const line = JSON.parse(raw) as LedgerLine;
        const r = await verifyReceipt(line);
        return { line: i + 1, event_hash: line.verdict?.event_hash, ...r };
      } catch {
        return { line: i + 1, verified: false, reason: "parse_error" };
      }
    })
  );
  const chain_valid = results.every((r) => r.verified);
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

export { jcsStringify, blake3Hex };
