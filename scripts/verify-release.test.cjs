const assert = require("node:assert/strict");
const test = require("node:test");

const { verifyRelease } = require("./verify-release.cjs");

function validInputs() {
  const manifest = {
    name: "@os1221/varp",
    version: "1.0.0",
    repository: { url: "https://github.com/os1221/varp-sdk" },
    publishConfig: {
      access: "public",
      registry: "https://registry.npmjs.org/",
    },
  };
  const lockfile = {
    name: "@os1221/varp",
    version: "1.0.0",
    packages: {
      "": { name: "@os1221/varp", version: "1.0.0" },
    },
  };
  return { manifest, lockfile, releaseTag: "v1.0.0" };
}

test("accepts aligned manifest, lockfile root, and release tag", () => {
  assert.deepEqual(verifyRelease(validInputs()), []);
});

test("rejects a lockfile root package name from another package", () => {
  const inputs = validInputs();
  inputs.lockfile.packages[""].name = "@os1221/not-varp";

  assert.deepEqual(verifyRelease(inputs), [
    "package-lock.json root name must match package.json: @os1221/not-varp != @os1221/varp",
  ]);
});

test("rejects a lockfile root version from another release", () => {
  const inputs = validInputs();
  inputs.lockfile.packages[""].version = "0.9.0";

  assert.deepEqual(verifyRelease(inputs), [
    "package-lock.json root version must match package.json: 0.9.0 != 1.0.0",
  ]);
});

test("rejects top-level lockfile identity drift", () => {
  const inputs = validInputs();
  inputs.lockfile.name = "@os1221/not-varp";
  inputs.lockfile.version = "0.9.0";

  assert.deepEqual(verifyRelease(inputs), [
    "package-lock.json name must match package.json: @os1221/not-varp != @os1221/varp",
    "package-lock.json version must match package.json: 0.9.0 != 1.0.0",
  ]);
});

test("rejects a lockfile without a root package record", () => {
  const inputs = validInputs();
  delete inputs.lockfile.packages[""];

  assert.deepEqual(verifyRelease(inputs), [
    "package-lock.json must contain a packages[\"\"] root record",
  ]);
});
