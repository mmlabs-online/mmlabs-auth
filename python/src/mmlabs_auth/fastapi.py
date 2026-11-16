"""FastAPI integration (extra `mmlabs-auth[fastapi]`) for app backends (not `admin`).

`MmlabsAuth(...).require_permission("<app>:<resource>:<action>")` is a dependency that returns
a `Principal`. Errors use the R6 envelope `{"error": {"code", "message", "details"}}` once
`register_exception_handler(app)` is called; without it the status and headers stay correct.
"""

import logging
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastapi import FastAPI, HTTPException, Request, Security
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from mmlabs_auth.access_token import InvalidAccessTokenError
from mmlabs_auth.authz import permits
from mmlabs_auth.catalog import ADMIN_APP_KEY, RoleCatalogCache
from mmlabs_auth.errors import CatalogConfigError, CatalogUnavailableError, JwksUnavailableError
from mmlabs_auth.jwks import JwksCache
from mmlabs_auth.verifier import AccessTokenVerifier

logger = logging.getLogger("mmlabs_auth")

DEFAULT_ISSUER = "https://api.mmlabs.online"
_UNAVAILABLE = (JwksUnavailableError, CatalogUnavailableError, CatalogConfigError)

bearer_scheme = HTTPBearer(scheme_name="bearerAuth", bearerFormat="JWT", auto_error=False)


@dataclass(frozen=True)
class Principal:
    sub: str
    email: str | None = field(repr=False)
    roles: tuple[str, ...]
    permissions: frozenset[str]
    jti: str
    claims: Mapping[str, Any] = field(repr=False)


class AuthHTTPError(HTTPException):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        details: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=message, headers=headers)
        self.code = code
        self.message = message
        self.details = details


async def _handle(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, AuthHTTPError):  # registered for AuthHTTPError only
        raise exc
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message, "details": exc.details}},
        headers=exc.headers,
    )


def register_exception_handler(app: FastAPI) -> None:
    app.add_exception_handler(AuthHTTPError, _handle)


def _unauthorized(*, token_sent: bool) -> AuthHTTPError:
    challenge = 'Bearer error="invalid_token"' if token_sent else "Bearer"
    return AuthHTTPError(
        401, "unauthorized", "Authentication required", headers={"WWW-Authenticate": challenge}
    )


def _unavailable() -> AuthHTTPError:
    return AuthHTTPError(503, "auth_unavailable", "Authentication temporarily unavailable")


class MmlabsAuth:
    def __init__(
        self,
        *,
        audience: str,
        user_agent: str,
        issuer: str = DEFAULT_ISSUER,
        api_base: str | None = None,
        jwks_url: str | None = None,
        leeway: int = 30,
        allow_insecure_loopback: bool = False,
    ) -> None:
        if audience == ADMIN_APP_KEY:
            raise ValueError("mmlabs-auth: the admin app is not supported (ADR-0008)")
        base = (api_base or issuer).rstrip("/")
        self.audience = audience
        self.jwks = JwksCache(
            jwks_url or f"{base}/.well-known/jwks.json",
            user_agent=user_agent,
            allow_insecure_loopback=allow_insecure_loopback,
        )
        self.catalog = RoleCatalogCache(
            base, audience, user_agent=user_agent, allow_insecure_loopback=allow_insecure_loopback
        )
        self.verifier = AccessTokenVerifier(
            self.jwks, audience=audience, issuer=issuer, leeway=leeway
        )
        self._permission_re = re.compile(
            rf"^{re.escape(audience)}:([a-z][a-z0-9-]{{0,47}}:[a-z][a-z0-9-]{{0,47}}|\*)$"
        )

    def require_permission(self, permission: str) -> Callable[..., Awaitable[Principal]]:
        """A dependency enforcing `permission`; `ValueError` now if it is not of this app."""
        if not self._permission_re.fullmatch(permission):
            raise ValueError(f"mmlabs-auth: invalid permission for {self.audience!r}")

        async def dependency(
            credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
        ) -> Principal:
            return await self._authorize(credentials, permission)

        return dependency

    async def aclose(self) -> None:
        await self.jwks.aclose()
        await self.catalog.aclose()

    async def _authorize(
        self, credentials: HTTPAuthorizationCredentials | None, permission: str
    ) -> Principal:
        if credentials is None or not credentials.credentials:
            logger.info("mmlabs_auth_denied reason=missing")
            raise _unauthorized(token_sent=False)
        try:
            claims = await self.verifier.verify(credentials.credentials)
        except InvalidAccessTokenError as exc:
            logger.info("mmlabs_auth_denied reason=%s", exc.reason)
            raise _unauthorized(token_sent=True) from None
        except _UNAVAILABLE as exc:
            logger.warning("mmlabs_auth_unavailable error=%s", type(exc).__name__)
            raise _unavailable() from None
        jti = str(claims["jti"])
        raw_roles = claims.get("roles")
        roles = (
            tuple(r for r in raw_roles if isinstance(r, str)) if isinstance(raw_roles, list) else ()
        )
        try:
            permissions = await self.catalog.permissions_for(roles)
        except _UNAVAILABLE as exc:
            logger.warning("mmlabs_auth_unavailable error=%s jti=%s", type(exc).__name__, jti)
            raise _unavailable() from None
        if not permits(permissions, permission):
            logger.info("mmlabs_auth_permission_denied jti=%s required=%s", jti, permission)
            raise AuthHTTPError(
                403, "permission_denied", "Missing permission", details={"required": permission}
            )
        email = claims.get("email")
        return Principal(
            sub=str(claims["sub"]),
            email=email if isinstance(email, str) else None,
            roles=roles,
            permissions=permissions,
            jti=jti,
            claims=claims,
        )
