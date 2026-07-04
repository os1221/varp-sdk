# varp-sdk architecture

> Hand-authored agent docs (2026-07-04), pending OpenWiki tool repair.

## Design

Single-module SDK (`src/index.ts`, ~850 lines) + thin CLI (`src/cli.ts`).
Zero native binaries; WebCrypto-based so the same source builds for Node
(cjs/esm via tsup) and browser (esbuild ESM + IIFE bundles, `node:crypto`
externalized).

## Protocol (VERDICT/v1 canon)

1. `canonical = jcsStringify(receipt)` — RFC 8785 canonical JSON
2. `content_hash = blake3Hex(canonical)`
3. `signature = ed25519_sign(utf8(content_hash_hex))` — signature is over the
   hex *string* of the hash, matching Rust `verdict-crypto` and Python
   `verdict-cli` byte-for-byte (golden vectors prove it)

Chain integrity: each `LedgerLine` links to the previous via `prev_hash`.
Note (mesh lesson): `prev_hash` sits OUTSIDE the signed verdict, so chain-link
integrity is distinct from signature integrity — `verifyLedger` checks both
and reports them separately.

## Layers in src/index.ts

| Layer | Symbols |
|---|---|
| Receipt/ledger verify | `verifyReceipt`, `verifyLedger`, `parseLedger` |
| Signing | `createVerdictV1`, `getPublicKey`, `SignOptions` |
| Proof packets (`verdict.proof-packet/v1`) | `validateProofPacket`, `verifyProofPacket`, `verifyWarrantProofPacket` — verifies public Meridian/Warrant packets against report fixtures |
| Crypto primitives | `jcsStringify`, `blake3Hex`, `sha256Hex`, `ed25519Verify`, hex helpers |
| Types | `VerifyResult`, `WarrantPacketVerifyResult`, `VerdictV1Envelope`, `OmegaReceiptEvent/Verdict`, `LedgerLine`, `ProofPacketVerifyResult` |

## Test suite (node --test, 116 passing)

- `varp.test.js` — core sign/verify/ledger behavior
- `conformance.test.js` — cross-language golden vectors
- `proof-packet.test.js` + vendored `proof_packet_vectors.json`
- `parity-manifest.test.js` — sha256-pinned fixture drift gate (pins vendored
  from `parity/manifest.json`)
- `roundtrip.test.js`, `cli.test.js`, `safe-harbor.test.js` (2026-07,
  safe-harbor verifier behavior)

## Mesh position

varp-sdk is the TS/JS signer leg of the mesh trust spine. Cross-language byte
parity with verdict-cli (Python), the-court (TS), sports-mcp, and omega-kernel
verdict-crypto (Rust) is enforced by `parity/check_parity.py`
via `parity/legs/leg_varp_sdk.mjs`. Canonicalization drift (e.g. shallow-sort
JCS bugs) is the repeated defect class this guards against.
