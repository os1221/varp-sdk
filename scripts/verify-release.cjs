#!/usr/bin/env node

function verifyRelease({ manifest, lockfile, releaseTag }) {
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

  if (lockfile.name !== manifest.name) {
    failures.push(
      `package-lock.json name must match package.json: ${lockfile.name} != ${manifest.name}`,
    );
  }

  if (lockfile.version !== manifest.version) {
    failures.push(
      `package-lock.json version must match package.json: ${lockfile.version} != ${manifest.version}`,
    );
  }

  const lockRoot = lockfile.packages?.[""];
  if (!lockRoot) {
    failures.push('package-lock.json must contain a packages[""] root record');
  } else {
    if (lockRoot.name !== manifest.name) {
      failures.push(
        `package-lock.json root name must match package.json: ${lockRoot.name} != ${manifest.name}`,
      );
    }
    if (lockRoot.version !== manifest.version) {
      failures.push(
        `package-lock.json root version must match package.json: ${lockRoot.version} != ${manifest.version}`,
      );
    }
  }

  if (!releaseTag) {
    failures.push("set RELEASE_TAG to the GitHub Release tag (for example, v1.0.0)");
  } else if (releaseTag !== expectedTag) {
    failures.push(`release tag must be exactly ${expectedTag}, got ${releaseTag}`);
  }

  return failures;
}

function main() {
  const manifest = require("../package.json");
  const lockfile = require("../package-lock.json");
  const releaseTag = process.env.RELEASE_TAG || process.argv[2];
  const failures = verifyRelease({ manifest, lockfile, releaseTag });

  if (failures.length > 0) {
    for (const failure of failures) {
      console.error(`release verification failed: ${failure}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log(`${manifest.name}@${manifest.version} is aligned with release tag ${releaseTag}`);
}

if (require.main === module) main();

module.exports = { verifyRelease };
