# VARP SDK - npm Publish Instructions

## Prerequisites
1. npm account with `@os1221` scope
2. 2FA enabled (required for public packages)
3. `npm login` completed

## Publish Steps

```bash
# 1. Ensure clean build
cd /Users/personal/Projects/varp-sdk
npm run build

# 2. Verify tests pass
npm test

# 3. Check package contents
npm pack --dry-run

# 4. Login (if not already)
npm login --scope=@os1221 --registry=https://registry.npmjs.org/

# 5. Publish
npm publish --access public

# 6. Verify
npm view @os1221/varp@1.0.0
```

## Package Details
- **Name:** @os1221/varp
- **Version:** 1.0.0
- **License:** MIT
- **Registry:** npmjs.org (public)
- **Access:** public
- **Binary:** `varp` CLI

## CI/CD Alternative (GitHub Actions)
If manual publish fails, use the GitHub Actions workflow:
1. Push tag `v1.0.0`
2. GitHub Actions runs build + test + publish automatically
3. Requires `NPM_TOKEN` secret in GitHub repo settings

## Post-Publish
- Update CHANGELOG.md with release notes
- Create GitHub release with artifacts
- Tag commit: `git tag v1.0.0 && git push origin v1.0.0`
