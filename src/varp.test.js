// @ts-check
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { sha512 } from "@noble/hashes/sha512";
import * as ed25519 from "@noble/ed25519";

// @noble/ed25519 v2 requires sha512Sync to be wired in Node.js
ed25519.etc.sha512Sync = (...msgs) => sha512(...msgs);

// Dynamic import since the SDK ships ESM
const sdk = await import("../dist/index.mjs");
const {
  verifyReceipt,
  verifyLedger,
  verifyWarrantProofPacket,
  createVerdictV1,
  hexToBytes,
  bytesToHex,
  hashContent,
  getPublicKey,
  parseLedger,
} = sdk;

// Test keypair (ephemeral — for tests only)
const TEST_PRIV = "0101010101010101010101010101010101010101010101010101010101010101";

describe("VARP SDK — @os1221/varp", () => {
  let sampleReceipt;

  before(async () => {
    sampleReceipt = await createVerdictV1({
      agent: "TestAgent",
      description: "unit test receipt",
      delta_sv: 0.1,
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
        delta_sv: 0.2,
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

    it("detects forged verdict.prev_hash (createVerdictV1 surface)", async () => {
      const r1 = await createVerdictV1({
        agent: "ChainA",
        description: "root",
        privateKeyHex: TEST_PRIV,
      });
      const r2 = await createVerdictV1({
        agent: "ChainA",
        description: "forged link",
        privateKeyHex: TEST_PRIV,
        prevHash: "deadbeef".repeat(8),
      });
      assert.equal(r2.verdict.prev_hash, "deadbeef".repeat(8));
      assert.equal(r2.prev_hash, undefined, "SDK places prev_hash on verdict, not top-level");
      const result = await verifyLedger([JSON.stringify(r1), JSON.stringify(r2)].join("\n"));
      assert.equal(result.results.every((r) => r.verified), true, "signatures still valid");
      assert.equal(result.chain_valid, false, "forged prev_hash must fail chain_valid");
    });

    it("accepts a correctly linked verdict.prev_hash chain", async () => {
      const r1 = await createVerdictV1({
        agent: "ChainA",
        description: "root",
        privateKeyHex: TEST_PRIV,
      });
      const r2 = await createVerdictV1({
        agent: "ChainA",
        description: "linked",
        privateKeyHex: TEST_PRIV,
        prevHash: r1.verdict.event_hash,
      });
      const result = await verifyLedger([JSON.stringify(r1), JSON.stringify(r2)].join("\n"));
      assert.equal(result.chain_valid, true);
    });

    it("also honors top-level line.prev_hash for external ledgers", async () => {
      const r1 = await createVerdictV1({
        agent: "ChainB",
        description: "root",
        privateKeyHex: TEST_PRIV,
      });
      const r2 = await createVerdictV1({
        agent: "ChainB",
        description: "external style",
        privateKeyHex: TEST_PRIV,
      });
      r2.prev_hash = "cafebabe".repeat(8);
      const result = await verifyLedger([JSON.stringify(r1), JSON.stringify(r2)].join("\n"));
      assert.equal(result.chain_valid, false);
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

  describe("public SDK surface", () => {
    it("does not expose stylometric attribution before the safe-to-claim contract lands", async () => {
      assert.equal("attributeLLM" in sdk, false);
    });
  });

  describe("verifyWarrantProofPacket", () => {
    const warrantReport = {
      generated_at: "2026-06-28T19:54:50+00:00",
      coverage_hash: "coverage-123",
      receipt: {
        ok: true,
        coverage_hash: "coverage-123",
        event_hash: "event-123",
        ledger: "redacted:omega-ledger",
        signer_pubkey: "pubkey-123",
        timestamp: "2026-06-28T19:54:50.843250+00:00",
      },
      repos: [
        {
          repo: "a",
          policy_generated: true,
          checks: {
            builtin_destructive_block: { decision: "block" },
            read_only_allows: { decision: "allow" },
            credential_requires_approval: { decision: "require_approval" },
          },
        },
        {
          repo: "b",
          policy_generated: true,
          checks: {
            builtin_destructive_block: { decision: "block" },
            read_only_allows: { decision: "allow" },
            credential_requires_approval: { decision: "block" },
          },
        },
      ],
      summary: { failures: [] },
    };

    async function packetFor(report) {
      const reportRaw = JSON.stringify(report, null, 2);
      const reportHash = "sha256:" + await hashContentSha256(reportRaw);
      return {
        packet: {
          schema: "meridian-warrant-proof-packet/0.1",
          status: "pass",
          generatedAt: report.generated_at,
          report: {
            evidencePath: "/proof/warrant-coverage/report.fixture.json",
            evidenceHash: reportHash,
            coverageHash: report.coverage_hash,
            repoCount: report.repos.length,
            policyGenerated: report.repos.filter((repo) => repo.policy_generated).length,
            policyMissing: 0,
            failures: 0,
          },
          preflight: {
            destructiveBlocks: 2,
            readOnlyAllows: 2,
            credentialGates: 2,
          },
          receipt: {
            status: "signed",
            eventHash: report.receipt.event_hash,
            coverageHash: report.receipt.coverage_hash,
            verification: {
              status: "unavailable",
              ledgerMatched: false,
              signatureVerified: false,
              chainLinked: false,
              reason: "private Omega ledger redacted from public fixture",
            },
          },
        },
        reportRaw,
      };
    }

    async function hashContentSha256(text) {
      const { createHash } = await import("node:crypto");
      return createHash("sha256").update(text, "utf8").digest("hex");
    }

    it("verifies public packet/report consistency while marking private ledger redacted", async () => {
      const { packet, reportRaw } = await packetFor(warrantReport);
      const result = await verifyWarrantProofPacket(packet, reportRaw);
      assert.equal(result.verified, true);
      assert.equal(result.status, "unavailable_private_ledger");
      assert.equal(result.private_ledger_status, "redacted");
      assert.equal(result.repo_count, 2);
      assert.equal(result.credential_gates, 2);
      assert.equal(result.receipt_event_hash, "event-123");
      assert.deepEqual(result.reasons, ["public_packet_verified_private_ledger_redacted"]);
    });

    it("rejects a tampered report hash", async () => {
      const { packet } = await packetFor(warrantReport);
      const tamperedRaw = JSON.stringify({ ...warrantReport, coverage_hash: "coverage-tampered" }, null, 2);
      const result = await verifyWarrantProofPacket(packet, tamperedRaw);
      assert.equal(result.verified, false);
      assert.equal(result.status, "invalid");
      assert.ok(result.reasons.includes("report_hash_mismatch"));
      assert.ok(result.reasons.includes("coverage_hash_mismatch"));
    });

    it("rejects mismatched receipt coverage hash", async () => {
      const { packet, reportRaw } = await packetFor(warrantReport);
      packet.receipt.coverageHash = "wrong";
      const result = await verifyWarrantProofPacket(packet, reportRaw);
      assert.equal(result.verified, false);
      assert.ok(result.reasons.includes("receipt_coverage_hash_mismatch"));
    });

    it("rejects missing private-ledger redaction status", async () => {
      const { packet, reportRaw } = await packetFor(warrantReport);
      packet.receipt.verification.status = "verified";
      delete packet.receipt.verification.reason;
      const result = await verifyWarrantProofPacket(packet, reportRaw);
      assert.equal(result.verified, false);
      assert.ok(result.reasons.includes("private_ledger_status_not_redacted"));
    });

    it("CLI verifies packet and report fixtures as JSON", async () => {
      const { packet, reportRaw } = await packetFor(warrantReport);
      const dir = mkdtempSync(join(tmpdir(), "varp-warrant-"));
      const packetPath = join(dir, "proof-packet.fixture.json");
      const reportPath = join(dir, "report.fixture.json");
      writeFileSync(packetPath, JSON.stringify(packet, null, 2));
      writeFileSync(reportPath, reportRaw);
      const proc = spawnSync(
        process.execPath,
        ["dist/cli.js", "verify-warrant-packet", packetPath, reportPath],
        { cwd: process.cwd(), encoding: "utf8" },
      );
      assert.equal(proc.status, 0, proc.stderr || proc.stdout);
      const parsed = JSON.parse(proc.stdout);
      assert.equal(parsed.verified, true);
      assert.equal(parsed.status, "unavailable_private_ledger");
      assert.equal(parsed.private_ledger_status, "redacted");
    });
  });
});
