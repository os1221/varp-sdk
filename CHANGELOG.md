# Changelog

All notable changes to `@os1221/varp` are documented here.

## [Unreleased]

### Fixed
- **`verifyLedger` chain integrity** — `createVerdictV1` / CLI `sign` store `prev_hash`
  on `verdict.prev_hash`, but `verifyLedger` only inspected top-level `line.prev_hash`.
  A forged envelope `prev_hash` previously left `chain_valid: true`. Now both surfaces
  are checked (regression tests added).
- README claimed `blake3Hex` had a SHA-256 fallback; implementation correctly refuses
  silent substitution (safe-harbor). Docs aligned.
- `gen-dts` omitted `ed25519Verify`, Omega receipt types, and `LedgerLine.prev_hash`.
- Stale `dist/chunk-*.mjs` artifacts could bloat `npm pack` (~350KB unpacked of dead
  chunks). Build now starts with a clean `dist/`.
- Declared `esbuild` as a direct devDependency (was only transitive via tsup).
- Test typo `deltaScore` → `delta_sv` (silent wrong-key; always used default 0.1).

### Added
- CLI `varp verify-proof-packet <packet-or-envelope.json>` for the
  `verdict.proof-packet/v1` contract.
- `verifyProofPacket(input)` / `validateProofPacket(packet)` / `PROOF_PACKET_SCHEMA` —
  cross-language verifier for `verdict.proof-packet/v1`, the monetized proof-packet
  wrapper produced by verdict-cli's `verdict.proof_packet` module (a DIFFERENT contract
  from `verifyWarrantProofPacket`'s `meridian-warrant-proof-packet/0.1`). Accepts a raw
  packet, `{ packet }`, a signed VERDICT/v1 envelope, or `{ envelope }`; validation rules
  and error strings mirror the Python `validate_proof_packet` one-for-one, including the
  `statement` ↔ `statement_sha256` binding check. Envelopes verify
  `BLAKE3(JCS(receipt))` and the Ed25519 signature over the content-hash hex.
- Golden proof-packet conformance vectors vendored byte-identically from
  `verdict-cli/tests/proof_packet_vectors.json` into
  `src/__fixtures__/proof_packet_vectors.json` (3 packets incl. adversarial
  non-ASCII/astral-key/ES-number canonicalization; signed with the PUBLIC RFC 8032 §7.1
  TEST 1 key), consumed by `src/proof-packet.test.js` — the executable proof that a
  packet produced by verdict-cli Python verifies in this SDK.
- Suite: 119 tests (was 116 after proof-packet; was 89 before that).

## [1.0.0] — 2026-06-27

### Added
- `verifyReceipt(line)` — verify a single VERDICT/v1 receipt (BLAKE3 hash + Ed25519 signature)
- `verifyLedger(jsonlText)` — batch-verify all receipts in a JSONL ledger with chain validity flag
- `createVerdictV1(opts)` — sign a new VERDICT/v1 receipt with an Ed25519 private key
- `hashContent(text)` — BLAKE3-hash a string, returning hex (convenience wrapper)
- `jcsStringify(val)` — RFC 8785 deterministic JSON serialisation
- `blake3Hex(data)` — BLAKE3 content hash (SHA-256 fallback was later **removed**; refuse silent substitution)
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
