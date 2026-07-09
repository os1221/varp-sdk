// Vector-manifest drift gate (repo-local parity harness).
//
// The canonical vector fixtures vendored in src/__fixtures__/ must match the
// sha256s pinned in src/__fixtures__/parity_manifest.json (vendored from
// parity/manifest.json). If a fixture is edited without a
// coordinated cross-repo sweep, THIS repo's CI fails — no more silent
// cross-language divergence while every local suite stays green.
// Runs inside the normal suite: npm test (node --test src/*.test.js).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..");
const manifest = JSON.parse(
  readFileSync(join(here, "__fixtures__", "parity_manifest.json"), "utf8")
);

test("parity manifest declares its provenance", () => {
  assert.equal(manifest.schema, "mesh.parity-manifest/v1");
  assert.equal(manifest.source, "parity/manifest.json");
  assert.ok(Object.keys(manifest.files).length >= 2, "both vector fixtures must be pinned");
});

test("vendored vector fixtures match the pinned sha256s (cross-repo drift gate)", () => {
  for (const [rel, want] of Object.entries(manifest.files)) {
    const got = createHash("sha256")
      .update(readFileSync(join(repoRoot, rel)))
      .digest("hex");
    assert.equal(
      got,
      want,
      `${rel} drifted from parity/manifest.json — ` +
        "update only via a cross-repo vector sweep (see parity/README.md)"
    );
  }
});
