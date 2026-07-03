// @ts-check
// VERDICT/v1 conformance: this SDK must reproduce the canonical golden vectors
// (single source of truth: omega_kernel/crates/verdict-crypto/tests/conformance_vectors.json,
// vendored byte-identically in __fixtures__ — check-parity.sh compares copies by hash).
// If any assertion here fails, the SDK has drifted from the normative Rust
// implementation and its receipts are no longer third-party verifiable.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { sha512 } from "@noble/hashes/sha512";
import * as ed25519 from "@noble/ed25519";

ed25519.etc.sha512Sync = (...msgs) => sha512(...msgs);

const sdk = await import("../dist/index.mjs");
const { jcsStringify, blake3Hex } = sdk;

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  readFileSync(join(here, "__fixtures__", "conformance_vectors.json"), "utf8"),
);

const utf8 = (s) => new TextEncoder().encode(s);

describe("VERDICT/v1 conformance vectors (canonical golden set)", () => {
  for (const v of fixture.vectors) {
    if (v.expected_content_hash) {
      it(`${v.name}: JCS canonicalization matches golden`, () => {
        assert.equal(jcsStringify(v.receipt), v.expected_jcs);
      });

      it(`${v.name}: JCS→BLAKE3 content hash matches golden`, async () => {
        assert.equal(await blake3Hex(utf8(jcsStringify(v.receipt))), v.expected_content_hash);
      });

      it(`${v.name}: Ed25519 signature verifies over content-hash utf8 bytes`, () => {
        const ok = ed25519.verify(
          Uint8Array.from(Buffer.from(v.signature, "hex")),
          utf8(v.expected_content_hash),
          Uint8Array.from(Buffer.from(v.signer_pubkey, "hex")),
        );
        assert.equal(ok, true);
      });
    }

    if (v.reused_content_hash_from) {
      it(`${v.name}: tampered payload recomputes to a DIFFERENT hash`, async () => {
        const original = fixture.vectors.find((x) => x.name === v.reused_content_hash_from);
        const recomputed = await blake3Hex(utf8(jcsStringify(v.receipt)));
        assert.notEqual(recomputed, original.expected_content_hash);
      });
    }
  }

  it("JCS is key-order invariant (adversarial reorder)", async () => {
    const m = fixture.vectors.find((v) => v.name === "minimal_approve");
    const reversed = (o) => {
      if (Array.isArray(o)) return o.map(reversed);
      if (o && typeof o === "object") {
        const out = {};
        for (const k of Object.keys(o).reverse()) out[k] = reversed(o[k]);
        return out;
      }
      return o;
    };
    assert.equal(
      await blake3Hex(utf8(jcsStringify(reversed(m.receipt)))),
      m.expected_content_hash,
    );
  });
});
