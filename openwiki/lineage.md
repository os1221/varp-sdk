# varp-sdk — lineage

## Timeline

- **2026-06-27** — first commit: "docs: add README.md for npm publish".
- **2026-06-28** — "feat(sdk): verify public warrant proof packets" (README's last
  touch to date).
- **2026-07-04** — most recent repo commit ("docs(openwiki): hand-authored
  quickstart + architecture agent docs").
- Only 3 README commits total — young, small, recently-started package.

## Mesh device presence

Not independently re-verified this pass. **npm status (2026-07-09):**
`@os1221/varp` is **not yet on the public registry** (`npm view` → 404).
`PUBLISH_README.md` + package metadata are publish-ready; human must run
`npm publish --access public` after 2FA login. Runtime footprint today is
git clone / local `npm pack`, not a global install base.

## Relation to mesh timeline

Started 2026-06-27 — the youngest of the four "lineage-only" repos in this batch
(related protocol tooling), about 9 weeks after MBP
[timeline redacted] and roughly contemporaneous with [related tooling]'s
entire June-2026 development burst.
