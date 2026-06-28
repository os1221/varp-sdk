// @ts-check
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { sha512 } from "@noble/hashes/sha512";
import * as ed25519 from "@noble/ed25519";

// @noble/ed25519 v2 requires sha512Sync to be wired in Node.js
ed25519.etc.sha512Sync = (...msgs) => sha512(...msgs);

// Dynamic import since the SDK ships ESM
const { verifyReceipt, verifyLedger, createVerdictV1, hexToBytes, bytesToHex, hashContent, getPublicKey, parseLedger } = await import("../dist/index.mjs");

// Test keypair (ephemeral — for tests only)
const TEST_PRIV = "0101010101010101010101010101010101010101010101010101010101010101";

describe("VARP SDK — @os1221/varp", () => {
  let sampleReceipt;

  before(async () => {
    sampleReceipt = await createVerdictV1({
      agent: "TestAgent",
      description: "unit test receipt",
      deltaScore: 0.1,
      privateKeyHex: TEST_PRIV,
    });
  });

  describe("createVerdictV1", () => {
    it("returns a LedgerLine with a verdict field", async () => {
      assert.ok(sampleReceipt, "receipt should be truthy");
      assert.ok(sampleReceipt.verdict, "verdict field must exist");
    });

    it("verdict has required VARP fields", async () => {
      const v = sampleReceipt.verdict;
      assert.equal(typeof v.event_hash, "string", "event_hash must be string");
      assert.equal(typeof v.signature, "string", "signature must be string");
      assert.equal(typeof v.signer_pubkey, "string", "signer_pubkey must be string");
      assert.equal(typeof v.timestamp, "string", "timestamp must be string");
      assert.equal(v.agent, "TestAgent");
      assert.equal(v.description, "unit test receipt");
    });

    it("event_hash is 64 hex chars (BLAKE3-256)", async () => {
      assert.match(sampleReceipt.verdict.event_hash, /^[0-9a-f]{64}$/);
    });

    it("signature is 128 hex chars (Ed25519)", async () => {
      assert.match(sampleReceipt.verdict.signature, /^[0-9a-f]{128}$/);
    });

    it("signer_pubkey matches derived public key", async () => {
      const { getPublicKey } = await import("@noble/ed25519");
      const privBytes = hexToBytes(TEST_PRIV);
      const pubBytes = getPublicKey(privBytes);
      const expectedPub = bytesToHex(pubBytes);
      assert.equal(sampleReceipt.verdict.signer_pubkey, expectedPub);
    });
  });

  describe("verifyReceipt", () => {
    it("returns verified:true for a freshly created receipt", async () => {
      const result = await verifyReceipt(sampleReceipt);
      assert.equal(result.verified, true, `expected verified but got: ${result.reason}`);
    });

    it("detects hash tampering", async () => {
      const tampered = JSON.parse(JSON.stringify(sampleReceipt));
      tampered.verdict.description = "TAMPERED description";
      const result = await verifyReceipt(tampered);
      assert.equal(result.verified, false);
      assert.equal(result.reason, "hash_mismatch");
    });

    it("detects signature tampering", async () => {
      const tampered = JSON.parse(JSON.stringify(sampleReceipt));
      tampered.verdict.signature = tampered.verdict.signature.replace(/[0-9a-f]{4}$/, "0000");
      const result = await verifyReceipt(tampered);
      assert.equal(result.verified, false);
    });

    it("returns no_verdict_field (skipped/true) for missing verdict", async () => {
      const result = await verifyReceipt({});
      // null/missing verdict lines are skipped gracefully (matching Rust's continue behavior)
      assert.equal(result.reason, "no_verdict_field");
    });

    it("returns missing_fields when event_hash absent", async () => {
      const bad = { verdict: { agent: "x", description: "y", timestamp: "z", delta_sv: 0 } };
      const result = await verifyReceipt(bad);
      assert.equal(result.verified, false);
      assert.equal(result.reason, "missing_fields");
    });
  });

  describe("verifyLedger", () => {
    it("verifies a single-line JSONL ledger", async () => {
      const line = JSON.stringify(sampleReceipt);
      const result = await verifyLedger(line);
      assert.equal(result.results.length, 1);
      assert.equal(result.results[0].verified, true);
    });

    it("verifies a multi-receipt ledger", async () => {
      const r2 = await createVerdictV1({
        agent: "TestAgent2",
        description: "second receipt",
        deltaScore: 0.2,
        privateKeyHex: TEST_PRIV,
      });
      const jsonl = [JSON.stringify(sampleReceipt), JSON.stringify(r2)].join("\n");
      const result = await verifyLedger(jsonl);
      assert.equal(result.results.length, 2);
      assert.ok(result.results.every((r) => r.verified), "all receipts should verify");
    });

    it("reports invalid for a tampered line in a multi-line ledger", async () => {
      const tampered = JSON.parse(JSON.stringify(sampleReceipt));
      tampered.verdict.description = "evil";
      const jsonl = [JSON.stringify(tampered), JSON.stringify(sampleReceipt)].join("\n");
      const result = await verifyLedger(jsonl);
      assert.equal(result.results[0].verified, false);
      assert.equal(result.results[1].verified, true);
    });
  });

  describe("hashContent", () => {
    it("returns 64 hex chars (BLAKE3-256)", async () => {
      const hex = await hashContent("receipts not vibes");
      assert.match(hex, /^[0-9a-f]{64}$/);
    });

    it("is deterministic — same input, same hash", async () => {
      const h1 = await hashContent("deterministic");
      const h2 = await hashContent("deterministic");
      assert.equal(h1, h2);
    });

    it("is sensitive — one char change produces different hash", async () => {
      const h1 = await hashContent("receipts not vibes");
      const h2 = await hashContent("receipts not vibeS");
      assert.notEqual(h1, h2);
    });

    it("known vector: BLAKE3('receipts not vibes')", async () => {
      const hex = await hashContent("receipts not vibes");
      assert.equal(hex, "f38f885d7d1bfb8f404c1e1974c07f959a47449e5abe09b18575fbd35e8a1e7d");
    });
  });

  describe("hexToBytes / bytesToHex round-trip", () => {
    it("round-trips a 32-byte value", () => {
      const original = "deadbeef".repeat(8);
      assert.equal(bytesToHex(hexToBytes(original)), original);
    });

    it("round-trips all-zeros", () => {
      const original = "00".repeat(32);
      assert.equal(bytesToHex(hexToBytes(original)), original);
    });
  });

  describe("getPublicKey", () => {
    it("returns 64-char hex public key for known private key", async () => {
      const pub = await getPublicKey(TEST_PRIV);
      assert.equal(typeof pub, "string");
      assert.equal(pub.length, 64);
      assert.match(pub, /^[0-9a-f]+$/);
    });

    it("is deterministic — same private key always yields same public key", async () => {
      const pub1 = await getPublicKey(TEST_PRIV);
      const pub2 = await getPublicKey(TEST_PRIV);
      assert.equal(pub1, pub2);
    });

    it("different private keys yield different public keys", async () => {
      const privB = "0202020202020202020202020202020202020202020202020202020202020202";
      const pub1 = await getPublicKey(TEST_PRIV);
      const pub2 = await getPublicKey(privB);
      assert.notEqual(pub1, pub2);
    });

    it("public key from getPublicKey matches signer_pubkey in receipt", async () => {
      const pub = await getPublicKey(TEST_PRIV);
      assert.equal(sampleReceipt.verdict.signer_pubkey, pub);
    });
  });

  describe("parseLedger", () => {
    it("parses single-entry JSONL string", async () => {
      const line = JSON.stringify(sampleReceipt);
      const entries = parseLedger(line);
      assert.equal(entries.length, 1);
      assert.ok(entries[0].verdict, "should have verdict field");
    });

    it("parses multi-entry JSONL string", async () => {
      const r1 = await createVerdictV1({ agent: "A1", description: "first", privateKeyHex: TEST_PRIV });
      const r2 = await createVerdictV1({ agent: "A2", description: "second", privateKeyHex: TEST_PRIV });
      const jsonl = [r1, r2].map(r => JSON.stringify(r)).join("\n");
      const entries = parseLedger(jsonl);
      assert.equal(entries.length, 2);
      assert.equal(entries[0].verdict.agent, "A1");
      assert.equal(entries[1].verdict.agent, "A2");
    });

    it("skips malformed lines silently", () => {
      const jsonl = '{"verdict":{}}\n{bad json\n{"verdict":{"agent":"ok"}}';
      const entries = parseLedger(jsonl);
      assert.equal(entries.length, 2);
    });

    it("returns empty array for empty string", () => {
      assert.deepEqual(parseLedger(""), []);
    });

    it("handles trailing newline without error", async () => {
      const jsonl = JSON.stringify(sampleReceipt) + "\n";
      const entries = parseLedger(jsonl);
      assert.equal(entries.length, 1);
    });
  });
});
