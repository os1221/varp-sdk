#!/usr/bin/env node

const manifest = require("../package.json");

const releaseTag = process.env.RELEASE_TAG || process.argv[2];
const expectedTag = `v${manifest.version}`;
const failures = [];

if (manifest.name !== "@os1221/varp") {
  failures.push(`package name must be @os1221/varp, got ${manifest.name}`);
}

if (manifest.repository?.url !== "https://github.com/os1221/varp-sdk") {
  failures.push(
    `repository URL must exactly match https://github.com/os1221/varp-sdk, got ${manifest.repository?.url}`,
  );
}

if (manifest.publishConfig?.access !== "public") {
  failures.push("publishConfig.access must be public for this scoped package");
}

if (manifest.publishConfig?.registry !== "https://registry.npmjs.org/") {
  failures.push("publishConfig.registry must be https://registry.npmjs.org/");
}

if (!releaseTag) {
  failures.push("set RELEASE_TAG to the GitHub Release tag (for example, v1.0.0)");
} else if (releaseTag !== expectedTag) {
  failures.push(`release tag must be exactly ${expectedTag}, got ${releaseTag}`);
}

if (failures.length > 0) {
  for (const failure of failures) console.error(`release verification failed: ${failure}`);
  process.exit(1);
}

console.log(`${manifest.name}@${manifest.version} is aligned with release tag ${releaseTag}`);
