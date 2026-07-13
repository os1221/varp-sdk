# VARP SDK npm release runbook

`@os1221/varp` is intended to be a public scoped package. As of 2026-07-12, it does not exist on npm, so `npm install @os1221/varp` returns `E404`.

The release design has two deliberately separate phases:

1. One interactive bootstrap publish creates the package on npm from an already-created, protected, immutable Git tag.
2. Every later release uses GitHub Actions trusted publishing (OIDC), with no long-lived npm write token.

npm cannot attach a trusted publisher to a package that does not exist yet. The workflow therefore cannot safely automate the very first publish.

## Package contract

- Name: `@os1221/varp`
- Access: public (also enforced by `package.json#publishConfig`)
- Registry: `https://registry.npmjs.org/`
- License: MIT
- Binary: `varp`
- Source: `https://github.com/os1221/varp-sdk`

## 1. Freeze and protect the bootstrap source

Complete the release metadata, commit it, and push the commit. Before creating any package artifact, configure an active GitHub tag ruleset for `v*` that restricts tag creation to release maintainers and blocks tag updates and deletion. Create `v1.0.0` only after that rule is active; never move or recreate a release tag.

From the release commit:

```bash
export RELEASE_TAG=v1.0.0
test -z "$(git status --porcelain)"
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
git tag --annotate "$RELEASE_TAG" --message "@os1221/varp 1.0.0"
git push origin "$RELEASE_TAG"
git fetch --tags origin
test "$(git rev-parse HEAD)" = "$(git rev-parse "refs/tags/${RELEASE_TAG}^{commit}")"
test -z "$(git status --porcelain)"
```

The final two checks are the source-identity gate: the clean working tree's `HEAD` must be the protected tag's commit before dependency installation, build, packing, or publication begins. If any check fails, stop and prepare a new version; never repair a release by moving the tag.

## 2. Build and inspect the bootstrap artifact

Use Node 24 and npm 11.5.1 or newer. From a clean checkout:

```bash
npm ci
npm test
npm run verify:package
RELEASE_TAG="$RELEASE_TAG" npm run release:verify

artifact_dir="$(mktemp -d)"
npm pack --pack-destination "$artifact_dir"
package_count="$(find "$artifact_dir" -maxdepth 1 -type f -name '*.tgz' | wc -l | tr -d ' ')"
test "$package_count" = '1'
tarball="$(find "$artifact_dir" -maxdepth 1 -type f -name '*.tgz' -print)"
shasum -a 256 "$tarball"
tar -tzf "$tarball"
```

Inspect both the fail-closed verifier output and the exact tarball listing. They must contain the compiled `dist/` entry points, README, license, changelog, and package manifest, and must not contain source, local caches, dependency trees, backups, lockfiles, or nested tarballs. Keep the `tarball` shell variable and its printed SHA-256; the next step publishes that exact file, not the working directory and not a repack.

## 3. Bootstrap the first package version once

This is the only release that cannot use trusted publishing. It requires an npm account that controls the `@os1221` scope, account-level 2FA, and an interactive npm login or another npm-supported short-lived manual authentication method.

```bash
npm login --scope=@os1221 --registry=https://registry.npmjs.org/
npm publish "$tarball" --access public
npm view @os1221/varp@1.0.0 name version dist.tarball dist.integrity
expected_integrity="$(node -e 'const { createHash } = require("node:crypto"); const { readFileSync } = require("node:fs"); process.stdout.write(`sha512-${createHash("sha512").update(readFileSync(process.argv[1])).digest("base64")}`)' "$tarball")"
published_integrity="$(npm view @os1221/varp@1.0.0 dist.integrity)"
test "$published_integrity" = "$expected_integrity"
```

Do not add an `NPM_TOKEN` GitHub secret. Confirm the registry response has the intended name and version; the final equality check proves npm serves the exact inspected tarball by comparing its SHA-512 SRI value. Retain the local SHA-256 in the release record. The protected `v1.0.0` tag already exists and identifies the source that produced the tarball; never create it after publishing and never move it. Do not publish a `v1.0.0` GitHub Release: that would correctly run the workflow after trusted publishing is configured, and npm would reject the already-existing immutable version.

## 4. Configure trusted publishing after bootstrap

In the npm package settings for `@os1221/varp`, add a GitHub Actions trusted publisher with these exact values:

- Organization/user: `os1221`
- Repository: `varp-sdk`
- Workflow filename: `publish.yml`
- Environment: `npm`
- Allowed action: `npm publish`

In GitHub, create the protected `npm` deployment environment. Require at least one reviewer, enable prevention of self-review, and set deployment branches and tags to **Selected branches and tags** with only the protected `v*` tag pattern allowed. The repository's active `v*` tag ruleset must continue to restrict creation to release maintainers and block updates and deletion. These are release requirements, not optional hardening.

GitHub plan and repository-visibility rules can limit required reviewers or deployment tag filters. If this repository's current plan does not expose every required control, do not use the automated publish workflow yet: keep releases manual with two-person review until the repository is public or the plan supports the protections. Do not silently weaken the environment to make OIDC publication run.

Trusted publishing requires a GitHub-hosted runner, Node 22.14 or newer, npm 11.5.1 or newer, and `id-token: write`. This repository uses Node 24 and grants the OIDC permission only to the publish job. For a public repository and public package, npm automatically creates provenance attestations; do not add `--provenance` or a publish token.

## 5. Publish subsequent versions

1. Update `package.json` and `package-lock.json` to the same new version.
2. Move release notes from `Unreleased` into the matching `CHANGELOG.md` version.
3. Run the verification commands above with `RELEASE_TAG=v<package-version>`.
4. Commit and push the clean release candidate.
5. Create and publish a non-prerelease GitHub Release whose tag is exactly `v<package-version>`.

`.github/workflows/publish.yml` checks out the exact release tag without persisting GitHub credentials, proves that `HEAD` is that tag's commit, then runs tests and a fail-closed npm pack inspection without OIDC permission. `release:verify` also requires the top-level and root package records in `package-lock.json` to match `package.json`, so a version bump cannot leave the reproducible-install contract behind. The workflow uploads that exact tarball with a SHA-256 manifest. Only after that job succeeds does the protected `npm` environment publish job receive `id-token: write`; that job verifies the artifact digest and publishes without reinstalling dependencies or running their lifecycle scripts. Both jobs independently enforce source identity, package name, repository, public access, and exact tag/version match.

The separate `Verdict Attest` workflow depends on private `verdict-cli` credentials and pins the dependency to reviewed commit `629d08ad55e53cc51402e224a0794f7b5215f5b0`; push Verdict through that commit before pushing this workflow. Its current missing `VERDICT_CLI_DEPLOY_KEY` can leave that attestation lane red, but it is intentionally not a dependency of npm package verification or publishing. Update the pinned commit only through a reviewed VARP change—never follow a floating Verdict branch in an attestation job.

## Failure modes

- `E404` before bootstrap: expected; complete the one-time manual first publish.
- `ENEEDAUTH` in the publish job: confirm the npm trusted-publisher fields, workflow filename, and `npm` environment match exactly.
- Tag mismatch: rename/recreate the GitHub Release so its tag is exactly `v<package.json version>`; never edit the workflow to bypass the guard.
- Version already exists: bump the package version and changelog. npm package versions are immutable.
- OIDC succeeds but no provenance appears: confirm both the GitHub repository and npm package are public and that provenance has not been disabled.
