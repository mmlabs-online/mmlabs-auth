# mmlabs-auth (Python)

Server-side verification of **mmlabs Identity** access tokens for app backends: JWKS cache,
ES256 verification (`iss`, `aud`, `exp`, `typ`, `email_verified`), role-catalog cache with ETag,
the `permits()` matcher, and a FastAPI `require_permission()` dependency.

API contract: [`org-admin-api/docs/consumers.md`](https://github.com/mmlabs-online/org-admin-api/blob/main/docs/consumers.md).
If this library and that page disagree, the page wins and the library gets a fix.

## 1. Install

Not on PyPI. Each release is tagged `py-vX.Y.Z` and its wheel is attached to the GitHub Release.
The repository is public, so no GitHub token is needed.

```bash
# From the tag (git subdirectory install)
uv add "mmlabs-auth[fastapi] @ git+https://github.com/mmlabs-online/mmlabs-auth@py-v0.1.0#subdirectory=python"

# Or vendor the wheel from the Release (no network access to GitHub at build time)
V=0.1.0
curl -fsSLo vendor/mmlabs_auth-$V-py3-none-any.whl \
  https://github.com/mmlabs-online/mmlabs-auth/releases/download/py-v$V/mmlabs_auth-$V-py3-none-any.whl
sha256sum vendor/mmlabs_auth-$V-py3-none-any.whl   # compare with the release notes
uv add "mmlabs-auth[fastapi] @ ./vendor/mmlabs_auth-$V-py3-none-any.whl"
```

Python ≥ 3.12. Runtime dependencies: `PyJWT[crypto]`, `httpx`. The `fastapi` extra adds FastAPI;
`import mmlabs_auth` never imports it.

## 2. Quick start (FastAPI)

```python
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI
from mmlabs_auth.fastapi import MmlabsAuth, Principal, register_exception_handler

auth = MmlabsAuth(audience="ricotdin", user_agent="ricotdin-api/1.4")


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await auth.aclose()


app = FastAPI(lifespan=lifespan)
register_exception_handler(app)  # R6 envelope {"error": {"code", "message", "details"}}

NotesReader = Annotated[Principal, Depends(auth.require_permission("ricotdin:notes:read"))]


@app.get("/notes")
async def list_notes(principal: NotesReader) -> list[dict]:
    return await notes_for(principal.sub)
```

`MmlabsAuth(*, audience, user_agent, issuer="https://api.mmlabs.online", api_base=None,
jwks_url=None, leeway=30, allow_insecure_loopback=False)`:

- `audience` is your app key. The token's `aud` must equal it (a list `aud` is rejected).
- `api_base` defaults to `issuer`; `jwks_url` defaults to `<api_base>/.well-known/jwks.json`.
- `allow_insecure_loopback=True` allows `http://localhost`, `127.0.0.1` and `[::1]`, for local
  development only. Every other URL must be `https://`.
- `require_permission(perm)` checks `perm` when the route is defined: it must be
  `<audience>:<resource>:<action>` or `<audience>:*`, otherwise `ValueError`.

The dependency returns `Principal(sub, email, roles, permissions, jti, claims)` (frozen; `email`
and `claims` are left out of its `repr`). Responses:

| Case | Status | `error.code` | Notes |
|---|---|---|---|
| No `Authorization: Bearer …` | 401 | `unauthorized` | `WWW-Authenticate: Bearer` |
| Token invalid (any reason) | 401 | `unauthorized` | `WWW-Authenticate: Bearer error="invalid_token"`; the reason is logged, never returned |
| Permission missing | 403 | `permission_denied` | `details: {"required": "<perm>"}` |
| JWKS or catalog unavailable, catalog 404 | 503 | `auth_unavailable` | Fail closed; not a 401, so clients do not loop on token refresh |

Without `register_exception_handler`, `AuthHTTPError` (an `HTTPException`) still carries the right
status and headers, with FastAPI's default `{"detail": …}` body.

## 3. Other frameworks: the pure verifier

```python
from mmlabs_auth import (
    AccessTokenVerifier,
    InvalidAccessTokenError,
    JwksCache,
    RoleCatalogCache,
    permits,
)

jwks = JwksCache(
    "https://api.mmlabs.online/.well-known/jwks.json", user_agent="ricotdin-worker/1.4"
)
verifier = AccessTokenVerifier(jwks, audience="ricotdin", issuer="https://api.mmlabs.online")
catalog = RoleCatalogCache(
    "https://api.mmlabs.online", "ricotdin", user_agent="ricotdin-worker/1.4"
)

try:
    claims = await verifier.verify(token)
except InvalidAccessTokenError as exc:
    log.info("token rejected reason=%s", exc.reason)  # never log the token
    raise
perms = await catalog.permissions_for(claims.get("roles", []))
if not permits(perms, "ricotdin:notes:read"):
    ...
```

`verify_access_token(token, keys, *, audience, issuer, leeway=30)` is the synchronous core, a
verbatim copy of the server's verifier with the same reason codes: `malformed`, `typ`, `alg`,
`kid`, `signature`, `expired`, `audience`, `issuer`, `claims`, `email_verified`. `keys` maps
`kid` to an EC P-256 public key. It requires header `typ: at+jwt`, `alg: ES256` and a known `kid`
(≤ 128 characters), claims `exp`, `iat`, `sub`, `jti`, `iss`, `aud`, and `email_verified: true`.
`leeway` above 30 s raises `ValueError`. Only the header `kid` selects a key: `jku`, `x5u` and
`jwk` headers are ignored.

`permits(granted, required)` matches exactly or by the app wildcard `<app>:*`. There is no global
`*` and no `<app>:<resource>:*`.

## 4. Cache behaviour

All fetches: HTTPS only, redirects are never followed, 3 s connect / 5 s total timeout, a
`User-Agent` and `If-None-Match` on every request, TLS verification always on.

**JWKS** (`JwksCache`, body cap 64 KB):

- Fresh for `Cache-Control: max-age` (capped at 1 h; 300 s when absent). A 304 keeps the keys and
  extends the TTL.
- A token with an unknown `kid` triggers at most **one refetch per 60 s** (also after a failed
  fetch). Concurrent callers share one fetch.
- Only `kty=EC`, `crv=P-256` keys with `alg` ES256 (or absent) and `use` sig (or absent) are kept.
- When a refresh fails, the last good keys are served up to 1 h after the last successful fetch,
  and no new fetch is tried for 60 s. After that: `JwksUnavailableError` → 503.

**Role catalog** (`RoleCatalogCache`, body cap 256 KB):

- Revalidated at most once per **60 s** with `If-None-Match`; a 304 confirms the cached catalog.
- During an outage (5xx, 429, timeout, bad shape) the last good catalog is served for up to
  **15 min** after it was last confirmed; then `CatalogUnavailableError` → 503.
- A 404 means an unknown or disabled app key: `CatalogConfigError` → 503. Fix the configuration.
- Permissions without your `<app>:` prefix are dropped. Roles not in the catalog grant nothing.

A failed first fetch at startup means 503 for up to 60 s (the cooldown); start the identity API
first or accept the short window.

## 5. Emergency key rotation

When a signing key is withdrawn, call `auth.jwks.flush()` (or `JwksCache.flush()`) in every
process. It drops the keys, the ETag and the cooldowns; the next request fetches the JWKS again,
so tokens signed with the withdrawn key fail at once instead of after the cache TTL.

## 6. App backends only

`audience="admin"` and `RoleCatalogCache(..., "admin")` raise `ValueError`. Admin permissions come
from the org-admin-api database, not from token roles (ADR-0008); the admin API verifies its own
tokens.

## 7. Map roles only through the catalog

Never hard-code `role → permission` tables, and never treat a role key as a permission. Roles are
edited by admins in the catalog; `permissions_for(roles)` is the only mapping.

## 8. Logging

Logger `mmlabs_auth`. It logs the rejection reason code and, after verification, the token `jti`
and the required permission. It never logs the token, the `Authorization` header or the email.
Exceptions carry fixed messages (no URL, body or token). Do the same in your own logs.

## 9. Revocation lag

Access tokens live up to 15 min and are verified locally, so a logout, a removed membership or a
changed role takes effect only when the current token expires (catalog changes: within 60 s of
revalidation). Design sensitive actions with that in mind.
