# mmlabs-auth

Client libraries for **mmlabs Identity** (`mmlabs-online/org-admin-api`).

| Directory | Package | What it does | Guide |
|---|---|---|---|
| `ts/` | `@mmlabs/auth-client` | Browser client: sign-in, account choice, per-app access tokens, logout; React wrapper | [`ts/README.md`](ts/README.md) |
| `python/` | `mmlabs-auth` | Backend: access-token verification (JWKS, ES256), role catalog cache, FastAPI `require_permission()` | [`python/README.md`](python/README.md) |
| `contract/` | — | Error codes and example responses taken from org-admin-api; `SOURCE` holds the commit they came from | — |

API contract: [`org-admin-api/docs/consumers.md`](https://github.com/mmlabs-online/org-admin-api/blob/main/docs/consumers.md).
If a library and that page disagree, the page wins and the library gets a fix.
Work is tracked in org-admin-api as ticket USR-08.

## Development

Requirements: Node 22 with pnpm 10 (`ts/package.json` `packageManager`), and `uv` (Python 3.12).

```bash
# TypeScript
pnpm -C ts install --frozen-lockfile
pnpm -C ts lint
pnpm -C ts typecheck
pnpm -C ts test
pnpm -C ts build

# Python
uv sync --locked --directory python
uv run --directory python ruff check .
uv run --directory python ruff format --check .
uv run --directory python mypy
uv run --directory python pytest
```

Both suites must be green before every commit. CI runs the same steps (`.github/workflows/ts.yml`, `python.yml`).
Lockfiles (`ts/pnpm-lock.yaml`, `python/uv.lock`) are committed; installs are frozen. `ts/.npmrc` disables install scripts.

## Install

The repository is public: installs need no GitHub token. Neither package is on a registry.

- TypeScript: download the `mmlabs-auth-client-X.Y.Z.tgz` asset of the `ts-vX.Y.Z` Release, check
  its SHA-256 against the release notes and vendor it (`pnpm add ./vendor/mmlabs-auth-client-X.Y.Z.tgz`).
  Details: [`ts/README.md`](ts/README.md#1-install).
- Python: `uv add "mmlabs-auth[fastapi] @ git+https://github.com/mmlabs-online/mmlabs-auth@py-vX.Y.Z#subdirectory=python"`,
  or vendor the wheel from the `py-vX.Y.Z` Release. Details: [`python/README.md`](python/README.md#1-install).

## Releases

Independent semver per package (0.x), tagged `ts-vX.Y.Z` and `py-vX.Y.Z`. To release, bump the
version in `ts/package.json` or `python/pyproject.toml`, merge to `main`, then push the tag.
`.github/workflows/release.yml` checks that the tag matches the version, runs the full suite,
builds and creates the GitHub Release with SHA-256 sums in the notes.
Rationale: [`docs/adr/0001-packaging-and-release.md`](docs/adr/0001-packaging-and-release.md).

No `LICENSE` yet (pending the owner's decision).
