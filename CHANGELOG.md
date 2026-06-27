# Changelog

All notable changes to `@os1221/varp` are documented here.

## [1.0.0] — 2026-06-27

### Added
- `verifyReceipt(line)` — verify a single VERDICT/v1 receipt (BLAKE3 hash + Ed25519 signature)
- `verifyLedger(jsonlText)` — batch-verify all receipts in a JSONL ledger with chain validity flag
- `createVerdictV1(opts)` — sign a new VERDICT/v1 receipt with an Ed25519 private key
- `hashContent(text)` — BLAKE3-hash a string, returning hex (convenience wrapper)
- `jcsStringify(val)` — RFC 8785 deterministic JSON serialisation
- `blake3Hex(data)` — BLAKE3 with SHA-256 fallback for environments without the noble/hashes build
- `hexToBytes` / `bytesToHex` — hex encoding utilities
- **`varp` CLI** — `verify`, `verify-ledger`, `hash`, `help` commands via `npx @os1221/varp`
- 26 tests across 10 suites including CLI subprocess smoke tests and a known BLAKE3 test vector
- ESM + CJS dual exports; Node ≥ 18
- EU AI Act Article 13/14/22 compliant audit trail design

### Security
- BLAKE3 content hash binds the receipt payload to `event_hash` — any field alteration is detectable
- Ed25519 signature ties each receipt to the signer's key pair
- `prev_hash` chain linkage makes insertion, deletion, or reordering of receipts detectable offline
- No network dependency for verification — all primitives are self-contained

[1.0.0]: https://github.com/os1221/varp-sdk/releases/tag/v1.0.0
