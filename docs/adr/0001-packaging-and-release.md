# ADR-0001: Packaging and release

- Status: accepted
- Date: 2026-11-16
- Ticket: USR-08 (tracked in `mmlabs-online/org-admin-api`)

## Context

`mmlabs-auth` holds two client libraries for mmlabs Identity: `@mmlabs/auth-client` (TypeScript,
`ts/`) and `mmlabs-auth` (Python, `python/`). Consuming apps build in Docker and deploy through the
shared mmlabs deploy repo. They need a pinned, reproducible install that does not depend on a
registry account or on a GitHub token inside the build.

The repository has been **public since 2026-11-16**, so tags, source archives and Release assets
download without authentication.

## Decision

1. **Independent semver per package, at 0.x.** Tags are `ts-vX.Y.Z` (version in
   `ts/package.json`) and `py-vX.Y.Z` (version in `python/pyproject.toml`). A breaking change bumps
   the minor version while at 0.x.
2. **Release workflow** (`.github/workflows/release.yml`). Pushing a tag runs the package's full
   check suite, fails if the tag does not equal the manifest version, builds the artefacts and
   creates a GitHub Release with the SHA-256 of each artefact in the notes. It uses only
   `github.token`; `contents: write` is granted to the release jobs alone. No long-lived secrets.
3. **TypeScript ships as a Release tarball** (`mmlabs-auth-client-X.Y.Z.tgz`, from `pnpm pack`).
   Consumers download it, check the SHA-256 and vendor it into their own repo as
   `"@mmlabs/auth-client": "file:vendor/mmlabs-auth-client-X.Y.Z.tgz"`, so their Docker build never
   reaches GitHub.
4. **Python installs from the tag or the Release.** Either
   `mmlabs-auth @ git+https://github.com/mmlabs-online/mmlabs-auth@py-vX.Y.Z#subdirectory=python`,
   or the sdist/wheel attached to the Release (vendored the same way as the TS tarball).
5. **No registry yet.** Not npm, not PyPI. GitHub Packages was rejected: it forces the
   `@mmlabs-online` npm scope and needs a token even for public reads.
6. **`"private": true` stays in `ts/package.json`.** It only blocks an accidental `npm publish`;
   it has no effect on the tarball install.

## Consequences

- Installs need no token: the repository is public.
- Upgrading is explicit: a consumer changes the pinned tag or vendored file.
- Moving to a registry later is additive (publish the same artefacts); the tag scheme stays.
- **Deferred:** provenance / build attestations for Release artefacts.
- **Open:** the repository has no `LICENSE` yet. Public visibility does not grant reuse rights;
  the licence is pending the owner's decision.
