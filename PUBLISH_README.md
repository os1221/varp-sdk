# VARP SDK npm release runbook

`@os1221/varp` is intended to be a public scoped package. As of 2026-07-12, it does not exist on npm, so `npm install @os1221/varp` returns `E404`.

The release design has two deliberately separate phases:

1. One interactive bootstrap publish creates the package on npm.
2. Every later release uses GitHub Actions trusted publishing (OIDC), with no long-lived npm write token.

npm cannot attach a trusted publisher to a package that does not exist yet. The workflow therefore cannot safely automate the very first publish.

## Package contract

- Name: `@os1221/varp`
- Access: public (also enforced by `package.json#publishConfig`)
- Registry: `https://registry.npmjs.org/`
- License: MIT
- Binary: `varp`
- Source: `https://github.com/os1221/varp-sdk`

## 1. Verify the release candidate

Use Node 24 and npm 11.5.1 or newer. From a clean checkout:

```bash
npm ci
npm test
npm run verify:package
RELEASE_TAG=v1.0.0 npm run release:verify
```

Inspect the dry-run file list. It must contain the compiled `dist/` entry points, README, license, changelog, and package manifest, and must not contain source, local caches, dependency trees, backups, lockfiles, or nested tarballs. The fail-closed package verifier enforces this boundary before OIDC permission is granted.

## 2. Bootstrap the first package version once

This is the only release that cannot use trusted publishing. It requires an npm account that controls the `@os1221` scope, account-level 2FA, and an interactive npm login or another npm-supported short-lived manual authentication method.

```bash
npm login --scope=@os1221 --registry=https://registry.npmjs.org/
npm publish --access public
npm view @os1221/varp@1.0.0
```

Do not add an `NPM_TOKEN` GitHub secret. After npm confirms `1.0.0`, create the matching Git tag for source traceability, but do not publish a duplicate `v1.0.0` GitHub Release: a published release would correctly run the workflow and npm would reject the already-existing version.

## 3. Configure trusted publishing after bootstrap

In the npm package settings for `@os1221/varp`, add a GitHub Actions trusted publisher with these exact values:

- Organization/user: `os1221`
- Repository: `varp-sdk`
- Workflow filename: `publish.yml`
- Environment: `npm`
- Allowed action: `npm publish`

In GitHub, create the `npm` deployment environment. Add required reviewers if desired. Protect release tags so only maintainers can create `v*` tags. Once OIDC works, set npm publishing access to require 2FA and disallow traditional tokens, then revoke any obsolete automation tokens.

Trusted publishing requires a GitHub-hosted runner, Node 22.14 or newer, npm 11.5.1 or newer, and `id-token: write`. This repository uses Node 24 and grants the OIDC permission only to the publish job. For a public repository and public package, npm automatically creates provenance attestations; do not add `--provenance` or a publish token.

## 4. Publish subsequent versions

1. Update `package.json` and `package-lock.json` to the same new version.
2. Move release notes from `Unreleased` into the matching `CHANGELOG.md` version.
3. Run the verification commands above with `RELEASE_TAG=v<package-version>`.
4. Commit and push the clean release candidate.
5. Create and publish a non-prerelease GitHub Release whose tag is exactly `v<package-version>`.

`.github/workflows/publish.yml` checks out the exact release tag without persisting GitHub credentials, proves that `HEAD` is that tag's commit, then runs tests and a fail-closed npm pack inspection without OIDC permission. It uploads that exact tarball with a SHA-256 manifest. Only after that job succeeds does the protected `npm` environment publish job receive `id-token: write`; that job verifies the artifact digest and publishes without reinstalling dependencies or running their lifecycle scripts. Both jobs independently enforce source identity, package name, repository, public access, and exact tag/version match.

The separate `Verdict Attest` workflow depends on private `verdict-cli` credentials. Its current missing `VERDICT_CLI_DEPLOY_KEY` can leave that attestation lane red, but it is intentionally not a dependency of npm package verification or publishing.

## Failure modes

- `E404` before bootstrap: expected; complete the one-time manual first publish.
- `ENEEDAUTH` in the publish job: confirm the npm trusted-publisher fields, workflow filename, and `npm` environment match exactly.
- Tag mismatch: rename/recreate the GitHub Release so its tag is exactly `v<package.json version>`; never edit the workflow to bypass the guard.
- Version already exists: bump the package version and changelog. npm package versions are immutable.
- OIDC succeeds but no provenance appears: confirm both the GitHub repository and npm package are public and that provenance has not been disabled.
