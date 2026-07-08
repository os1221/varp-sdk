// @ts-check
// Safe Harbor guardrails: VERDICT/v1 must not silently downgrade to SHA-256,
// and npm package provenance must stay limited to the publishable runtime files.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha512 } from "@noble/hashes/sha512";
import * as ed25519 from "@noble/ed25519";

ed25519.etc.sha512Sync = (...msgs) => sha512(...msgs);

const sdk = await import("../dist/index.mjs");
const {
  createVerdictV1,
  verifyReceipt,
  jcsStringify,
  sha256Hex,
} = sdk;

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..");
const utf8 = (s) => new TextEncoder().encode(s);
const TEST_PRIV = "0101010101010101010101010101010101010101010101010101010101010101";

describe("Safe Harbor VERDICT/v1 no-downgrade guardrails", () => {
  it("rejects a receipt whose content hash is recomputed with SHA-256", async () => {
    const line = await createVerdictV1({
      agent: "SafeHarbor",
      description: "BLAKE3 only",
      delta_sv: 0.1,
      privateKeyHex: TEST_PRIV,
    });
    const payload = {
      agent: line.verdict.agent,
      description: line.verdict.description,
      timestamp: line.verdict.timestamp,
      delta_sv: line.verdict.delta_sv,
    };
    const sha256EventHash = await sha256Hex(utf8(jcsStringify(payload)));

    assert.notEqual(
      sha256EventHash,
      line.verdict.event_hash,
      "fixture sanity: SHA-256 digest must differ from VERDICT/v1 BLAKE3 digest",
    );

    const downgraded = JSON.parse(JSON.stringify(line));
    downgraded.verdict.event_hash = sha256EventHash;
    const result = await verifyReceipt(downgraded);

    assert.equal(result.verified, false);
    assert.equal(result.reason, "hash_mismatch");
  });
});

describe("Safe Harbor npm package provenance", () => {
  it("packs only runtime dist/docs/license files and excludes local source/cache artifacts", () => {
    const result = spawnSync("npm", ["pack", "--dry-run", "--json"], {
      cwd: repoRoot,
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr);

    const [pack] = JSON.parse(result.stdout);
    const paths = pack.files.map((file) => file.path).sort();

    for (const required of [
      "package.json",
      "README.md",
      "LICENSE",
      "CHANGELOG.md",
      "dist/index.js",
      "dist/index.mjs",
      "dist/index.d.ts",
      "dist/cli.js",
      "dist/cli.mjs",
    ]) {
      assert.ok(paths.includes(required), `expected package to include ${required}`);
    }

    for (const path of paths) {
      assert.equal(path.startsWith("src/"), false, `source file leaked into package: ${path}`);
      assert.equal(path.startsWith(".codebase-memory/"), false, `local graph artifact leaked into package: ${path}`);
      assert.equal(path.startsWith("node_modules/"), false, `dependency tree leaked into package: ${path}`);
      assert.equal(path.endsWith(".tgz"), false, `package tarball leaked into package: ${path}`);
      assert.notEqual(path, "package-lock.json", `lockfile should not be part of runtime package: ${path}`);
    }
  });
});
