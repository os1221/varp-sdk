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
});
