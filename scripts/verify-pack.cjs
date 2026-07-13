#!/usr/bin/env node

const { spawnSync } = require("node:child_process");

const result = spawnSync("npm", ["pack", "--dry-run", "--json"], {
  cwd: process.cwd(),
  encoding: "utf8",
});

if (result.status !== 0) {
  process.stderr.write(result.stderr || result.stdout);
  process.exit(result.status || 1);
}

let pack;
try {
  [pack] = JSON.parse(result.stdout);
} catch (error) {
  console.error(`package verification failed: npm pack did not return valid JSON: ${error.message}`);
  process.exit(1);
}

const failures = [];
const paths = (pack?.files || []).map((file) => file.path).sort();
const requiredPaths = [
  "CHANGELOG.md",
  "LICENSE",
  "README.md",
  "dist/cli.js",
  "dist/cli.mjs",
  "dist/index.d.ts",
  "dist/index.js",
  "dist/index.mjs",
  "dist/varp.browser.js",
  "dist/varp.browser.mjs",
  "package.json",
];

if (pack?.name !== "@os1221/varp") {
  failures.push(`packed name must be @os1221/varp, got ${pack?.name}`);
}

if (pack?.version !== require("../package.json").version) {
  failures.push(`packed version ${pack?.version} does not match package.json`);
}

for (const requiredPath of requiredPaths) {
  if (!paths.includes(requiredPath)) failures.push(`missing required file: ${requiredPath}`);
}

for (const path of paths) {
  const allowed =
    path === "CHANGELOG.md" ||
    path === "LICENSE" ||
    path === "README.md" ||
    path === "package.json" ||
    path.startsWith("dist/");
  if (!allowed) failures.push(`unexpected file outside the runtime package boundary: ${path}`);
  if (path.includes(".bak-")) failures.push(`backup file leaked into package: ${path}`);
  if (path.endsWith(".tgz")) failures.push(`nested package tarball leaked into package: ${path}`);
}

if (failures.length > 0) {
  for (const failure of failures) console.error(`package verification failed: ${failure}`);
  process.exit(1);
}

console.log(JSON.stringify({
  id: pack.id,
  filename: pack.filename,
  size: pack.size,
  unpackedSize: pack.unpackedSize,
  files: paths,
}, null, 2));
