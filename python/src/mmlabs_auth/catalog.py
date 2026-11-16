"""Async cache of an app's public role catalog `GET /api/v1/apps/{key}/roles` (D17).

- Revalidates with `If-None-Match` at most once per `min_revalidate` (60 s); a 304 confirms the
  cached catalog. The check time is recorded on failure too, so an outage is not hammered.
- On 5xx, 429, a timeout or a bad shape the last good catalog is served while it was last
  confirmed at most `max_stale` (15 min) ago; then `CatalogUnavailableError` (fail closed).
- 404 → `CatalogConfigError` (unknown or disabled app key); the cache is dropped.
- Permissions without the `<app_key>:` prefix are dropped; unknown roles grant nothing.
- `app_key="admin"` is refused: admin permissions come from the database (ADR-0008).
"""

import asyncio
import re
import time
from collections.abc import Callable, Iterable
from typing import Any

from mmlabs_auth._http import FetchError, check_url, fetch_json, new_client
from mmlabs_auth.errors import CatalogConfigError, CatalogUnavailableError

APP_KEY_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")  # org-admin-api app/modules/rbac/models.py
ADMIN_APP_KEY = "admin"


def _parse_catalog(body: Any, app_key: str) -> dict[str, frozenset[str]] | None:
    if not isinstance(body, dict) or body.get("app") != app_key:
        return None
    roles = body.get("roles")
    if not isinstance(roles, list):
        return None
    prefix = f"{app_key}:"
    parsed: dict[str, frozenset[str]] = {}
    for role in roles:
        if not isinstance(role, dict):
            return None
        key, permissions = role.get("key"), role.get("permissions")
        if not isinstance(key, str) or not isinstance(permissions, list):
            return None
        if not all(isinstance(p, str) for p in permissions):
            return None
        if key.startswith(prefix):
            parsed[key] = frozenset(p for p in permissions if p.startswith(prefix))
    return parsed


class RoleCatalogCache:
    def __init__(
        self,
        api_base: str,
        app_key: str,
        *,
        user_agent: str,
        min_revalidate: float = 60,
        max_stale: float = 900,
        max_bytes: int = 262_144,
        allow_insecure_loopback: bool = False,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if app_key == ADMIN_APP_KEY:
            raise ValueError("mmlabs-auth: the admin app is not supported (ADR-0008)")
        if not APP_KEY_RE.fullmatch(app_key):
            raise ValueError("mmlabs-auth: invalid app key")
        self._url = f"{api_base.rstrip('/')}/api/v1/apps/{app_key}/roles"
        check_url(self._url, allow_insecure_loopback=allow_insecure_loopback)
        self._app_key = app_key
        self._allow_insecure_loopback = allow_insecure_loopback
        self._min_revalidate = min_revalidate
        self._max_stale = max_stale
        self._max_bytes = max_bytes
        self._clock = clock
        self._client = new_client(user_agent)
        self._lock = asyncio.Lock()
        self._roles: dict[str, frozenset[str]] | None = None
        self._etag: str | None = None
        self._ok_at: float | None = None  # last 200 or 304
        self._checked_at: float | None = None  # last attempt
        self._not_found = False

    async def permissions_for(self, roles: Iterable[str]) -> frozenset[str]:
        """Union of the permissions of `roles`; roles not in the catalog add nothing."""
        catalog = await self._catalog()
        granted: set[str] = set()
        for role in roles:
            if isinstance(role, str):
                granted |= catalog.get(role, frozenset())
        return frozenset(granted)

    async def aclose(self) -> None:
        await self._client.aclose()

    def _due(self) -> bool:
        return self._checked_at is None or self._clock() - self._checked_at >= self._min_revalidate

    async def _catalog(self) -> dict[str, frozenset[str]]:
        if self._due():
            async with self._lock:
                if self._due():
                    await self._refresh()
        if self._not_found:
            raise CatalogConfigError()
        if (
            self._roles is None
            or self._ok_at is None
            or self._clock() - self._ok_at > self._max_stale
        ):
            raise CatalogUnavailableError()
        return self._roles

    async def _refresh(self) -> None:
        self._checked_at = self._clock()
        try:
            result = await fetch_json(
                self._client,
                self._url,
                etag=self._etag if self._roles is not None else None,
                max_bytes=self._max_bytes,
                allow_insecure_loopback=self._allow_insecure_loopback,
            )
        except FetchError:
            return
        if result.status == 404:
            self._not_found = True
            self._roles = self._etag = self._ok_at = None
            return
        if result.status == 304 and self._roles is not None:
            self._ok_at = self._clock()
            self._not_found = False
            return
        if result.status != 200:
            return
        parsed = _parse_catalog(result.body, self._app_key)
        if parsed is None:
            return
        self._roles, self._etag, self._ok_at = parsed, result.etag, self._clock()
        self._not_found = False
