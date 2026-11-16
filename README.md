# mmlabs-auth

Client libraries for **mmlabs Identity** (`mmlabs-online/org-admin-api`):

- `ts/` — `@mmlabs/auth-client`: browser client (sign-in, account choice, per-audience access tokens, logout) with a React wrapper.
- `python/` — `mmlabs-auth`: server-side access-token verification (JWKS, ES256), role catalog cache and a FastAPI `require_permission()` dependency.

API contract and integration guide: [`org-admin-api/docs/consumers.md`](https://github.com/mmlabs-online/org-admin-api/blob/main/docs/consumers.md).
Work is tracked in org-admin-api as ticket USR-08.
