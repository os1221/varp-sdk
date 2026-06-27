# @os1221/varp

**Verifiable AI Receipt Protocol** — cryptographic provenance for AI outputs.

Ed25519-signed, BLAKE3-hashed, JCS-canonicalized receipt chains. EU AI Act Article 13 compliant. Zero infrastructure beyond a writable file path.

## Install

```bash
npm install @os1221/varp
```

## Quick start

```typescript
import { verifyReceipt, createVerdictV1, verifyLedger } from "@os1221/varp";

// Verify a single receipt from a ledger line
const result = await verifyReceipt(JSON.parse(ledgerLine));
console.log(result.verified ? "✓ verified" : `✗ ${result.reason}`);

// Verify an entire JSONL ledger file
const { results, chain_valid } = await verifyLedger(fs.readFileSync("receipts.jsonl", "utf8"));
console.log(`${results.filter(r => r.verified).length}/${results.length} verified, chain: ${chain_valid}`);

// Create a new signed receipt
const receipt = await createVerdictV1({
  agent: "MyAgent",
  description: "Task completed: ran integration test suite",
  delta_sv: 0.1,
  privateKeyHex: process.env.AGENT_KEY_HEX!, // 64-char hex Ed25519 seed
});
```

## API

### `verifyReceipt(line: LedgerLine): Promise<VerifyResult>`
Verify a single VERDICT/v1 receipt. Checks BLAKE3 content hash and Ed25519 signature.

### `verifyLedger(jsonlText: string): Promise<{ results, chain_valid }>`
Verify all receipts in a JSONL ledger string. Returns per-line results and overall chain validity.

### `createVerdictV1(opts: SignOptions): Promise<LedgerLine>`
Sign a new VERDICT/v1 receipt with an Ed25519 private key.

### `hexToBytes(hex: string): Uint8Array`
### `bytesToHex(bytes: Uint8Array): string`
### `jcsStringify(val: unknown): string` — deterministic JSON (RFC 8785)
### `blake3Hex(data: Uint8Array): Promise<string>` — BLAKE3 hash, fallback to SHA-256

## Receipt format (VERDICT/v1)

```json
{
  "verdict": {
    "event_hash": "blake3hex...",
    "signature": "ed25519hex...",
    "signer_pubkey": "pubkeyhex...",
    "prev_hash": "blake3hex...",
    "timestamp": "2026-06-27T07:00:00.000Z",
    "delta_sv": 0.1,
    "description": "human-readable summary",
    "agent": "AgentName"
  }
}
```

## Live demo

Browser-side verification (no auth): [os1221.com/ops/receipts](https://os1221.com/ops/receipts)

Read the VARP paper: [os1221.com/verdict](https://os1221.com/verdict)

## License

MIT — Omair Shahid
