# @os1221/varp

[![npm](https://img.shields.io/npm/v/@os1221/varp)](https://www.npmjs.com/package/@os1221/varp)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![tests](https://img.shields.io/badge/tests-28%20passing-brightgreen)](src/varp.test.js)
[![cli](https://img.shields.io/badge/cli-varp-blue)]()

**Verifiable AI Receipt Protocol** — cryptographic provenance for every AI agent action.

Sign any AI decision with Ed25519 + BLAKE3 + JCS (RFC 8785). Build an append-only, tamper-evident audit chain. Verify the full history offline with no cloud dependency. Designed for EU AI Act Article 13/14/22 compliance and agentic systems that need to prove what happened.

## Why VARP?

AI agents take consequential actions — running code, sending messages, calling APIs. When something goes wrong (or right), you need to prove:

- **What** happened (description, agent name)
- **When** (cryptographically-timestamped, not just logged)
- **That the record hasn't been altered** (BLAKE3 content hash + Ed25519 signature)
- **Chain integrity** — each receipt links to the previous via `prev_hash`

VARP is the receipt format. This library is the verifier + signer. Zero infrastructure beyond a writable file path.

## Install

```bash
npm install @os1221/varp
```

Node ≥ 18. ESM + CJS exports. No native binaries. Includes a `varp` CLI.

## CLI

```bash
# Verify a single receipt file
npx @os1221/varp verify receipt.json

# Verify all receipts in a JSONL ledger
npx @os1221/varp verify-ledger receipts.jsonl

# Hash any string with BLAKE3
npx @os1221/varp hash "receipts not vibes"
# → f38f885d7d1bfb8f404c1e1974c07f959a47449e5abe09b18575fbd35e8a1e7d
```

## Quick start

```typescript
import { verifyReceipt, createVerdictV1, verifyLedger } from "@os1221/varp";

// Verify a single receipt
const result = await verifyReceipt(JSON.parse(ledgerLine));
console.log(result.verified ? "✓ verified" : `✗ ${result.reason}`);

// Verify an entire JSONL ledger
const { results, chain_valid } = await verifyLedger(
  fs.readFileSync("receipts.jsonl", "utf8")
);
console.log(
  `${results.filter(r => r.verified).length}/${results.length} verified, chain: ${chain_valid}`
);

// Sign a new receipt
const receipt = await createVerdictV1({
  agent: "MyAgent",
  description: "Ran integration suite — 148 pass, 0 fail",
  delta_sv: 0.1,
  privateKeyHex: process.env.AGENT_KEY_HEX!, // 64-char hex Ed25519 seed
});
// Append JSON.stringify(receipt) + "\n" to your ledger file
```

## API

### `verifyReceipt(line: LedgerLine): Promise<VerifyResult>`
Verify a single VERDICT/v1 receipt. Checks BLAKE3 content hash and Ed25519 signature. Returns `{ verified: boolean, reason?: string }`.

### `verifyLedger(jsonlText: string): Promise<{ results: VerifyResult[], chain_valid: boolean }>`
Verify all receipts in a JSONL ledger string. Checks each line and validates `prev_hash` chain linkage.

### `createVerdictV1(opts: SignOptions): Promise<LedgerLine>`
Sign a new VERDICT/v1 receipt with an Ed25519 private key. Computes BLAKE3(JCS(body)) as `event_hash`.

### `hashContent(text: string): Promise<string>`
BLAKE3-hash a string, returning hex. Convenience wrapper for string inputs.

```typescript
const hex = await hashContent("receipts not vibes");
// f38f885d7d1bfb8f404c1e1974c07f959a47449e5abe09b18575fbd35e8a1e7d
```

### Utilities
- `hexToBytes(hex: string): Uint8Array`
- `bytesToHex(bytes: Uint8Array): string`
- `jcsStringify(val: unknown): string` — RFC 8785 deterministic JSON
- `blake3Hex(data: Uint8Array): Promise<string>` — BLAKE3 with SHA-256 fallback

## Receipt format (VERDICT/v1)

```json
{
  "verdict": {
    "event_hash":    "blake3hex...",
    "signature":     "ed25519hex...",
    "signer_pubkey": "pubkeyhex...",
    "prev_hash":     "blake3hex...",
    "timestamp":     "2026-06-27T07:00:00.000Z",
    "delta_sv":      0.1,
    "description":   "human-readable summary",
    "agent":         "AgentName"
  }
}
```

Each `prev_hash` must equal the `event_hash` of the preceding receipt. A broken chain is detectable offline — no server required.

## Security properties

- **Tamper-evident**: `event_hash = BLAKE3(JCS(verdict_body))` — altering any field changes the hash, breaking verification.
- **Attributable**: Ed25519 signature ties each receipt to a specific key pair you control.
- **Chain-linked**: `prev_hash` creates an ordered hash chain. Inserting, deleting, or reordering receipts is detectable.
- **Offline-verifiable**: No network calls needed to verify a ledger. All primitives are self-contained.

## Live demo

Browser-side verification (no auth): [os1221.com/ops/receipts](https://os1221.com/ops/receipts)

VARP paper + specification: [os1221.com/verdict](https://os1221.com/verdict)

Trust & privacy page: [os1221.com/meridian/trust](https://os1221.com/meridian/trust)

## License

MIT — Omair Shahid ([@os1221](https://github.com/os1221))
