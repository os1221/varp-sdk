# varp-sdk quickstart

> Hand-authored agent docs (2026-07-04), pending OpenWiki tool repair — the
> generator's OpenRouter key is an unfilled template and its local-MLX path
> fails on structured content blocks. Commands below were actually run.

`@os1221/varp` — **Verifiable AI Receipt Protocol** SDK + CLI (TypeScript,
MIT; package metadata publish-ready, **not yet on npm registry as of 2026-07-09**).
Signs AI agent actions with Ed25519 + BLAKE3 + JCS (RFC 8785) into an
append-only, tamper-evident chain; verifies fully offline.

## Build & test (verified 2026-07-04)

```bash
cd ~/Projects/varp-sdk
npm test        # pretest runs the full build, then node --test src/*.test.js
                # → 116 pass, 0 fail
npm run build   # tsup (cjs+esm) + gen-dts + esbuild browser bundles
```

Requires Node ≥ 18. Build outputs land in `dist/` (cjs, esm,
`varp.browser.mjs` ESM + `varp.browser.js` IIFE global `VARP`).

## CLI

```bash
npx @os1221/varp verify receipt.json
npx @os1221/varp verify-ledger receipts.jsonl
npx @os1221/varp verify-warrant-packet proof-packet.fixture.json report.fixture.json
npx @os1221/varp hash "receipts not vibes"
```

## API surface (src/index.ts)

- Verify: `verifyReceipt`, `verifyLedger`, `parseLedger`, `ed25519Verify`
- Sign: `createVerdictV1`, `getPublicKey`
- Proof packets: `validateProofPacket`, `verifyProofPacket`,
  `verifyWarrantProofPacket`, `PROOF_PACKET_SCHEMA` (`verdict.proof-packet/v1`)
- Primitives: `jcsStringify`, `blake3Hex`, `sha256Hex`, `hashContent`,
  `hexToBytes`, `bytesToHex`

## Parity & drift gates

- Golden vectors vendored at `src/__fixtures__/` (`conformance_vectors.json`,
  `proof_packet_vectors.json`) with sha256 pins in `parity_manifest.json`
  (checked by `src/parity-manifest.test.js`).
- Mesh-wide byte-parity leg: `parity/legs/leg_varp_sdk.mjs`.
- Never change hash/signature behavior without golden-vector coverage.

## Start here

- [Architecture](./architecture.md)
- `README.md` — protocol rationale, EU AI Act framing
- `examples/moat-demo.mjs`, `CHANGELOG.md`
