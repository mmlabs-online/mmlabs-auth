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

## Releases

Independent versions per package, tagged `ts-vX.Y.Z` and `py-vX.Y.Z`. Install instructions follow with the release workflow.
