# @os1221/varp

[![registry](https://img.shields.io/badge/npm-bootstrap%20pending-orange)](https://github.com/os1221/varp-sdk/blob/main/PUBLISH_README.md)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![tests](https://img.shields.io/badge/tests-119%20passing-brightgreen)](src/)
[![cli](https://img.shields.io/badge/cli-varp-blue)]()

**Verifiable AI Receipt Protocol** — cryptographic provenance for every AI agent action.

Sign any AI decision with Ed25519 + BLAKE3 + JCS (RFC 8785). Build an append-only, tamper-evident audit chain. Verify the full history offline with no cloud dependency. The resulting evidence can support transparency, record-keeping, and audit workflows; this library does not by itself make a system legally compliant.

## Why VARP?

AI agents take consequential actions — running code, sending messages, calling APIs. When something goes wrong (or right), you need to prove:

- **What** happened (description, agent name)
- **When claimed by the signer** (the supplied timestamp is signature-bound and tampering is detectable, but it is not independently time-attested)
- **That the record hasn't been altered** (BLAKE3 content hash + Ed25519 signature)
- **Chain integrity** — each receipt links to the previous via `prev_hash`

VARP is the receipt format. This library is the verifier + signer. Zero infrastructure beyond a writable file path.

## Install

> **Registry status (2026-07-12):** `@os1221/varp` has not completed its first npm registry publish yet. The registry command below becomes valid only after the [one-time bootstrap](https://github.com/os1221/varp-sdk/blob/main/PUBLISH_README.md). It is shown as the intended stable install surface, not as a claim that the package is already downloadable.

After the first registry release:

```bash
npm install @os1221/varp
```

Node ≥ 18. ESM + CJS exports. No native binaries. Includes a `varp` CLI.

Until then, verify the public source checkout directly:

```bash
git clone https://github.com/os1221/varp-sdk.git
cd varp-sdk
npm ci
npm test
npm pack --dry-run
```

## CLI

```bash
# Verify a single receipt file
npx @os1221/varp verify receipt.json

# Verify all receipts in a JSONL ledger
npx @os1221/varp verify-ledger receipts.jsonl

# Verify a public Meridian/Warrant proof packet against its report fixture
npx @os1221/varp verify-warrant-packet proof-packet.fixture.json report.fixture.json

# Verify a verdict.proof-packet/v1 (raw packet or signed envelope)
npx @os1221/varp verify-proof-packet packet-or-envelope.json

# Hash any string with BLAKE3
npx @os1221/varp hash "receipts not vibes"
# → f38f885d7d1bfb8f404c1e1974c07f959a47449e5abe09b18575fbd35e8a1e7d

# Sign / keygen / ledger inspect
npx @os1221/varp keygen
npx @os1221/varp sign --agent MyAgent --desc "task done" --key <hex64>
npx @os1221/varp summarize receipts.jsonl
npx @os1221/varp chain-report receipts.jsonl
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

### `verifyWarrantProofPacket(packet, reportTextOrObject): Promise<WarrantPacketVerifyResult>`
Verify public Meridian/Warrant proof-packet metadata against the exact public report fixture. It checks the report SHA-256 hash, coverage hash, repo/preflight counts, receipt event hash, and the public redaction state for the private Omega ledger.

### `verifyProofPacket(input): Promise<ProofPacketVerifyResult>` / `validateProofPacket(packet)`
Cross-language verifier for `verdict.proof-packet/v1` (the monetized packet from `verdict-cli` — a **different** contract from Meridian warrant packets). Accepts a raw packet, `{ packet }`, a signed VERDICT/v1 envelope, or `{ envelope }`. Envelopes verify `BLAKE3(JCS(receipt))` and Ed25519 over the content-hash hex.

### `createVerdictV1(opts: SignOptions): Promise<LedgerLine>`
Sign a new VERDICT/v1 receipt with an Ed25519 private key. Computes BLAKE3(JCS(body)) as `event_hash`. Optional `prevHash` is stored on `verdict.prev_hash` (outside the signed content payload) for chain linkage; `verifyLedger` checks it.

### `hashContent(text: string): Promise<string>`
BLAKE3-hash a string, returning hex. Convenience wrapper for string inputs.

```typescript
const hex = await hashContent("receipts not vibes");
// f38f885d7d1bfb8f404c1e1974c07f959a47449e5abe09b18575fbd35e8a1e7d
```

### Utilities
- `hexToBytes(hex: string): Uint8Array`
- `bytesToHex(bytes: Uint8Array): string`
- `jcsStringify(val: unknown): string` — RFC 8785 deterministic JSON (key-sorted; golden-vector locked)
- `blake3Hex(data: Uint8Array): Promise<string>` — BLAKE3 only (refuses silent SHA-256 substitution)
- `sha256Hex(data: Uint8Array): Promise<string>` — used for warrant report evidence hashes, not VERDICT content hashes
- `ed25519Verify(sigHex, message, pubHex): Promise<boolean>` — raw Ed25519 verify for browser verifiers
- `getPublicKey(privateKeyHex): Promise<string>`
- `parseLedger(jsonlText): LedgerLine[]`

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

## Verify a Meridian/Warrant proof packet

Public Warrant proof packets are designed for offline buyer verification without exposing a private Omega receipt ledger:

```bash
npx @os1221/varp verify-warrant-packet \
  proof-packet.fixture.json \
  report.fixture.json
```

Expected success shape:

```json
{
  "verified": true,
  "status": "unavailable_private_ledger",
  "private_ledger_status": "redacted"
}
```

`verified: true` means the public packet matches the public report fixture and its receipt metadata is internally consistent. `status: "unavailable_private_ledger"` is intentional: private Omega ledger continuity is redacted from public fixtures, so this command does not claim private chain/signature verification.

## Security properties

- **Tamper-evident**: `event_hash = BLAKE3(JCS(verdict_body))` — altering any field changes the hash, breaking verification.
- **Attributable**: Ed25519 signature ties each receipt to a specific key pair you control.
- **Chain-linked**: `prev_hash` creates an ordered hash chain. Inserting, deleting, or reordering receipts is detectable.
- **Offline-verifiable**: No network calls needed to verify a ledger. All primitives are self-contained.
- **Timestamp semantics**: The signer-supplied timestamp is part of the signed receipt, so changing it breaks verification. VARP alone does not prove that the claimed time was correct; independent time attestation requires an external trusted timestamp or transparency service.

## Live demo

Browser-side verification (no auth): [os1221.com/ops/receipts](https://os1221.com/ops/receipts)

VARP paper + specification: [os1221.com/verdict](https://os1221.com/verdict)

Trust & privacy page: [os1221.com/meridian/trust](https://os1221.com/meridian/trust)

## License

MIT — Omair Shahid ([@os1221](https://github.com/os1221))
