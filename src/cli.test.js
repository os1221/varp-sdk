// @ts-check
/**
 * CLI smoke tests — exercises dist/cli.js via child_process.
 * Each test spawns the CLI as a subprocess and checks exit code + stdout.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CLI = new URL("../dist/cli.js", import.meta.url).pathname;

function run(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    ...opts,
  });
}

describe("varp CLI", () => {
  describe("help", () => {
    it("exits 0 and prints usage", () => {
      const r = run(["help"]);
      assert.equal(r.status, 0, `exit ${r.status}: ${r.stderr}`);
      assert.match(r.stdout, /verify.*receipt\.json/);
      assert.match(r.stdout, /verify-ledger/);
      assert.match(r.stdout, /hash.*text/);
    });

    it("no-args shows help and exits 0", () => {
      const r = run([]);
      assert.equal(r.status, 0);
      assert.match(r.stdout, /varp —/);
    });
  });

  describe("version", () => {
    it("varp version prints semver and exits 0", () => {
      const r = run(["version"]);
      assert.equal(r.status, 0);
      assert.match(r.stdout.trim(), /^\d+\.\d+\.\d+$/);
    });

    it("varp --version also works", () => {
      const r = run(["--version"]);
      assert.equal(r.status, 0);
      assert.match(r.stdout.trim(), /^\d+\.\d+\.\d+$/);
    });
  });

  describe("hash", () => {
    it("outputs 64 hex chars for known input", () => {
      const r = run(["hash", "receipts not vibes"]);
      assert.equal(r.status, 0);
      assert.match(r.stdout.trim(), /^[0-9a-f]{64}$/);
    });

    it("known-vector: BLAKE3('receipts not vibes')", () => {
      const r = run(["hash", "receipts not vibes"]);
      assert.equal(r.stdout.trim(), "f38f885d7d1bfb8f404c1e1974c07f959a47449e5abe09b18575fbd35e8a1e7d");
    });

    it("multi-word args are joined", () => {
      const r1 = run(["hash", "hello world"]);
      const r2 = run(["hash", "hello", "world"]);
      assert.equal(r1.stdout.trim(), r2.stdout.trim());
    });
  });

  describe("verify", () => {
    let tmp;

    it("verifies a valid receipt file — exits 0", async () => {
      tmp = mkdtempSync(join(tmpdir(), "varp-cli-test-"));
      // Create a valid receipt using the SDK
      const { sha512 } = await import("@noble/hashes/sha512");
      const ed25519 = await import("@noble/ed25519");
      ed25519.etc.sha512Sync = (...msgs) => sha512(...msgs);
      const { createVerdictV1 } = await import("../dist/index.mjs");

      const receipt = await createVerdictV1({
        agent: "CLITestAgent",
        description: "cli smoke test",
        delta_sv: 0.1,
        privateKeyHex: "0101010101010101010101010101010101010101010101010101010101010101",
      });

      const path = join(tmp, "receipt.json");
      writeFileSync(path, JSON.stringify(receipt));

      const r = run(["verify", path]);
      assert.equal(r.status, 0, `exit ${r.status}: ${r.stderr}`);
      assert.match(r.stdout, /✓ verified/);

      rmSync(tmp, { recursive: true });
    });

    it("exits non-zero for a tampered receipt", async () => {
      tmp = mkdtempSync(join(tmpdir(), "varp-cli-test-"));
      const { sha512 } = await import("@noble/hashes/sha512");
      const ed25519 = await import("@noble/ed25519");
      ed25519.etc.sha512Sync = (...msgs) => sha512(...msgs);
      const { createVerdictV1 } = await import("../dist/index.mjs");

      const receipt = await createVerdictV1({
        agent: "CLITestAgent",
        description: "original",
        delta_sv: 0.1,
        privateKeyHex: "0101010101010101010101010101010101010101010101010101010101010101",
      });
      receipt.verdict.description = "TAMPERED";

      const path = join(tmp, "bad.json");
      writeFileSync(path, JSON.stringify(receipt));

      const r = run(["verify", path]);
      assert.notEqual(r.status, 0, "tampered receipt should exit non-zero");
      assert.match(r.stderr, /INVALID/);

      rmSync(tmp, { recursive: true });
    });
  });

  describe("sign", () => {
    const TEST_KEY = "0101010101010101010101010101010101010101010101010101010101010101";

    it("sign produces valid JSON with verdict field", () => {
      const r = run(["sign", "--agent", "CLIAgent", "--desc", "cli sign test", "--key", TEST_KEY]);
      assert.equal(r.status, 0, `exit ${r.status}: ${r.stderr}`);
      const parsed = JSON.parse(r.stdout);
      assert.ok(parsed.verdict, "must have verdict field");
      assert.equal(parsed.verdict.agent, "CLIAgent");
      assert.equal(parsed.verdict.description, "cli sign test");
      assert.equal(parsed.verdict.delta_sv, 0.1);
    });

    it("sign --sv sets delta_sv", () => {
      const r = run(["sign", "--agent", "A", "--desc", "d", "--key", TEST_KEY, "--sv", "0.5"]);
      assert.equal(r.status, 0);
      const parsed = JSON.parse(r.stdout);
      assert.equal(parsed.verdict.delta_sv, 0.5);
    });

    it("sign output verifies correctly", () => {
      const tmp = mkdtempSync(join(tmpdir(), "varp-sign-"));
      const r = run(["sign", "--agent", "A", "--desc", "round-trip", "--key", TEST_KEY]);
      const path = join(tmp, "signed.json");
      writeFileSync(path, r.stdout);
      const v = run(["verify", path]);
      assert.equal(v.status, 0, `verify failed: ${v.stderr}`);
      assert.match(v.stdout, /verified/);
      rmSync(tmp, { recursive: true });
    });

    it("sign errors without --agent", () => {
      const r = run(["sign", "--desc", "d", "--key", TEST_KEY]);
      assert.notEqual(r.status, 0, "should fail without --agent");
    });

    it("sign errors without --key and no env", () => {
      const r = run(["sign", "--agent", "A", "--desc", "d"], { env: { ...process.env, VARP_PRIVATE_KEY: "" } });
      assert.notEqual(r.status, 0, "should fail without key");
    });

    it("help shows sign command", () => {
      const r = run(["help"]);
      assert.match(r.stdout, /sign.*--agent.*--desc/s);
    });
  });

  describe("summarize", () => {
    const TEST_KEY = "0101010101010101010101010101010101010101010101010101010101010101";

    it("prints header and top agents for a multi-entry ledger", () => {
      const tmp = mkdtempSync(join(tmpdir(), "varp-sum-"));
      const r1 = run(["sign", "--agent", "AgentA", "--desc", "first", "--key", TEST_KEY]);
      const r2 = run(["sign", "--agent", "AgentA", "--desc", "second", "--key", TEST_KEY]);
      const r3 = run(["sign", "--agent", "AgentB", "--desc", "other", "--key", TEST_KEY]);
      const ledger = join(tmp, "ledger.jsonl");
      writeFileSync(ledger, [
        JSON.stringify(JSON.parse(r1.stdout)),
        JSON.stringify(JSON.parse(r2.stdout)),
        JSON.stringify(JSON.parse(r3.stdout)),
      ].join("\n") + "\n");
      const rs = run(["summarize", ledger]);
      assert.equal(rs.status, 0, `exit ${rs.status}: ${rs.stderr}`);
      assert.match(rs.stdout, /Total lines:\s+3/);
      assert.match(rs.stdout, /Unique agents:\s+2/);
      assert.match(rs.stdout, /AgentA/);
      assert.match(rs.stdout, /AgentB/);
      rmSync(tmp, { recursive: true });
    });

    it("help shows summarize", () => {
      const r = run(["help"]);
      assert.match(r.stdout, /summarize/);
    });
  });

  describe("keygen", () => {
    it("prints private_key and public_key in hex", () => {
      const r = run(["keygen"]);
      assert.equal(r.status, 0, `exit ${r.status}: ${r.stderr}`);
      assert.match(r.stdout, /private_key: [0-9a-f]{64}/);
      assert.match(r.stdout, /public_key:  [0-9a-f]{64}/);
    });

    it("each call generates a different key", () => {
      const r1 = run(["keygen"]);
      const r2 = run(["keygen"]);
      const priv1 = r1.stdout.match(/private_key: ([0-9a-f]{64})/)?.[1];
      const priv2 = r2.stdout.match(/private_key: ([0-9a-f]{64})/)?.[1];
      assert.ok(priv1 && priv2 && priv1 !== priv2, "keys must be unique");
    });

    it("generated key can be used to sign and verify", () => {
      const rk = run(["keygen"]);
      const privKey = rk.stdout.match(/private_key: ([0-9a-f]{64})/)?.[1];
      assert.ok(privKey, "expected private key");
      const tmp = mkdtempSync(join(tmpdir(), "varp-keygen-"));
      const rs = run(["sign", "--agent", "KeygenTest", "--desc", "generated-key", "--key", privKey]);
      assert.equal(rs.status, 0);
      const path = join(tmp, "receipt.json");
      writeFileSync(path, rs.stdout);
      const rv = run(["verify", path]);
      assert.equal(rv.status, 0, `verify failed: ${rv.stderr}`);
      assert.match(rv.stdout, /verified/);
      rmSync(tmp, { recursive: true });
    });

    it("help shows keygen", () => {
      const r = run(["help"]);
      assert.match(r.stdout, /keygen/);
    });
  });

  describe("chain-report", () => {
    const TEST_KEY = "0101010101010101010101010101010101010101010101010101010101010101";

    it("reports 0 breaks on a perfectly linked two-entry ledger", () => {
      const tmp = mkdtempSync(join(tmpdir(), "varp-chain-"));
      const r1 = run(["sign", "--agent", "A", "--desc", "first", "--key", TEST_KEY]);
      const receipt1 = JSON.parse(r1.stdout);
      const h1 = receipt1.verdict.event_hash;
      const r2 = run(["sign", "--agent", "A", "--desc", "second", "--key", TEST_KEY, "--prev-hash", h1]);
      const ledger = join(tmp, "ledger.jsonl");
      writeFileSync(ledger, [JSON.stringify(receipt1), JSON.stringify(JSON.parse(r2.stdout))].join("\n") + "\n");
      const cr = run(["chain-report", ledger]);
      assert.equal(cr.status, 0, `chain-report failed: ${cr.stderr}`);
      assert.match(cr.stdout, /0 chain break/);
      rmSync(tmp, { recursive: true });
    });

    it("detects a break when prev_hash is wrong", () => {
      const tmp = mkdtempSync(join(tmpdir(), "varp-chain-break-"));
      const r1 = run(["sign", "--agent", "A", "--desc", "first", "--key", TEST_KEY]);
      const receipt1 = JSON.parse(r1.stdout);
      const r2 = run(["sign", "--agent", "A", "--desc", "second", "--key", TEST_KEY, "--prev-hash", "deadbeef".repeat(8)]);
      const ledger = join(tmp, "ledger.jsonl");
      writeFileSync(ledger, [JSON.stringify(receipt1), JSON.stringify(JSON.parse(r2.stdout))].join("\n") + "\n");
      const cr = run(["chain-report", ledger]);
      assert.notEqual(cr.status, 0, "should detect chain break");
      assert.match(cr.stdout, /1 chain break/);
      rmSync(tmp, { recursive: true });
    });

    it("help shows chain-report", () => {
      const r = run(["help"]);
      assert.match(r.stdout, /chain-report/);
    });
  });
});
