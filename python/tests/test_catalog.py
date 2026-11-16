import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from mmlabs_auth import CatalogConfigError, CatalogUnavailableError, RoleCatalogCache
from tests.conftest import CATALOG_URL, UA, FakeClock

API = "https://api.mmlabs.online"
EXAMPLE = json.loads(
    (Path(__file__).resolve().parents[2] / "contract" / "catalog.example.json").read_text("utf-8")
)
BODY: dict[str, Any] = EXAMPLE["body"]


def _cache(clock: FakeClock) -> RoleCatalogCache:
    return RoleCatalogCache(API, "ricotdin", user_agent=UA, clock=clock)


def _ok(body: Any = BODY, etag: str = '"c1"') -> httpx.Response:
    return httpx.Response(200, json=body, headers={"ETag": etag, "Cache-Control": "no-cache"})


@respx.mock
async def test_permissions_union_of_roles(clock: FakeClock) -> None:
    respx.get(CATALOG_URL).mock(return_value=_ok())
    perms = await _cache(clock).permissions_for(["ricotdin:member", "ricotdin:admin"])
    assert perms == {"ricotdin:notes:read", "ricotdin:*"}


@respx.mock
async def test_unknown_role_grants_nothing(clock: FakeClock) -> None:
    respx.get(CATALOG_URL).mock(return_value=_ok())
    cache = _cache(clock)
    assert await cache.permissions_for(["ricotdin:ghost", "stoktok:admin"]) == frozenset()
    assert await cache.permissions_for([]) == frozenset()


@respx.mock
async def test_etag_304_keeps_body(clock: FakeClock) -> None:
    route = respx.get(CATALOG_URL).mock(side_effect=[_ok(), httpx.Response(304)])
    cache = _cache(clock)
    await cache.permissions_for(["ricotdin:member"])
    clock.advance(60)
    assert await cache.permissions_for(["ricotdin:member"]) == {"ricotdin:notes:read"}
    assert route.call_count == 2
    assert route.calls.last.request.headers["If-None-Match"] == '"c1"'
    assert route.calls.last.request.headers["User-Agent"] == UA


@respx.mock
async def test_no_revalidation_within_60s(clock: FakeClock) -> None:
    route = respx.get(CATALOG_URL).mock(return_value=_ok())
    cache = _cache(clock)
    await cache.permissions_for(["ricotdin:member"])
    clock.advance(59)
    await cache.permissions_for(["ricotdin:member"])
    assert route.call_count == 1


@respx.mock
async def test_revalidates_after_60s(clock: FakeClock) -> None:
    changed = {**BODY, "roles": [{**BODY["roles"][1], "permissions": ["ricotdin:notes:write"]}]}
    route = respx.get(CATALOG_URL).mock(side_effect=[_ok(), _ok(changed, '"c2"')])
    cache = _cache(clock)
    await cache.permissions_for(["ricotdin:member"])
    clock.advance(60)
    assert await cache.permissions_for(["ricotdin:member"]) == {"ricotdin:notes:write"}
    assert route.call_count == 2


@respx.mock
async def test_404_raises_config_error(clock: FakeClock) -> None:
    route = respx.get(CATALOG_URL).mock(side_effect=[_ok(), httpx.Response(404)])
    cache = _cache(clock)
    await cache.permissions_for(["ricotdin:member"])
    clock.advance(60)
    with pytest.raises(CatalogConfigError):
        await cache.permissions_for(["ricotdin:member"])
    with pytest.raises(CatalogConfigError):  # cached, no refetch within 60 s
        await cache.permissions_for(["ricotdin:member"])
    assert route.call_count == 2


@respx.mock
@pytest.mark.parametrize(
    "failure",
    [httpx.Response(503), httpx.Response(429), httpx.ConnectTimeout("t")],
    ids=["503", "429", "timeout"],
)
async def test_outage_serves_stale_up_to_15_min(clock: FakeClock, failure: Any) -> None:
    route = respx.get(CATALOG_URL).mock(return_value=_ok())
    cache = _cache(clock)
    await cache.permissions_for(["ricotdin:member"])
    if isinstance(failure, Exception):
        route.mock(side_effect=failure)
    else:
        route.mock(return_value=failure)
    for _ in range(15):
        clock.advance(60)
        assert await cache.permissions_for(["ricotdin:member"]) == {"ricotdin:notes:read"}
    assert route.call_count == 16


@respx.mock
async def test_outage_beyond_15_min_fails_closed(clock: FakeClock) -> None:
    route = respx.get(CATALOG_URL).mock(return_value=_ok())
    cache = _cache(clock)
    await cache.permissions_for(["ricotdin:member"])
    route.mock(return_value=httpx.Response(500))
    clock.advance(901)
    with pytest.raises(CatalogUnavailableError):
        await cache.permissions_for(["ricotdin:member"])


@respx.mock
async def test_no_cache_outage_fails_closed(clock: FakeClock) -> None:
    respx.get(CATALOG_URL).mock(side_effect=httpx.ReadTimeout("t"))
    with pytest.raises(CatalogUnavailableError):
        await _cache(clock).permissions_for(["ricotdin:member"])


@respx.mock
@pytest.mark.parametrize(
    "body",
    [
        [],
        {**BODY, "app": "stoktok"},
        {**BODY, "roles": "x"},
        {**BODY, "roles": [{"key": 1, "permissions": []}]},
        {**BODY, "roles": [{"key": "ricotdin:x", "permissions": [1]}]},
        {**BODY, "roles": ["ricotdin:x"]},
    ],
    ids=["list", "other-app", "roles-str", "key-int", "perm-int", "role-str"],
)
async def test_invalid_shape_keeps_last_good_or_fails_closed(clock: FakeClock, body: Any) -> None:
    route = respx.get(CATALOG_URL).mock(return_value=_ok(body))
    with pytest.raises(CatalogUnavailableError):
        await _cache(clock).permissions_for(["ricotdin:member"])
    route.mock(side_effect=[_ok(), _ok(body)])
    cache = _cache(clock)
    await cache.permissions_for(["ricotdin:member"])
    clock.advance(60)
    assert await cache.permissions_for(["ricotdin:member"]) == {"ricotdin:notes:read"}


@respx.mock
async def test_foreign_prefix_permissions_dropped(clock: FakeClock) -> None:
    body = {
        "app": "ricotdin",
        "roles": [
            {"key": "ricotdin:member", "permissions": ["ricotdin:notes:read", "admin:*", "*"]},
            {"key": "stoktok:admin", "permissions": ["stoktok:*"]},
        ],
    }
    respx.get(CATALOG_URL).mock(return_value=_ok(body))
    cache = _cache(clock)
    assert await cache.permissions_for(["ricotdin:member", "stoktok:admin"]) == {
        "ricotdin:notes:read"
    }


def test_admin_app_key_refused() -> None:
    with pytest.raises(ValueError):
        RoleCatalogCache(API, "admin", user_agent=UA)


@pytest.mark.parametrize("app_key", ["Ricotdin", "a", "../admin", "x/y"])
def test_invalid_app_key_refused(app_key: str) -> None:
    with pytest.raises(ValueError):
        RoleCatalogCache(API, app_key, user_agent=UA)


def test_http_api_base_refused() -> None:
    with pytest.raises(ValueError):
        RoleCatalogCache("http://api.mmlabs.online", "ricotdin", user_agent=UA)


@respx.mock
async def test_body_over_256kb_fails_closed(clock: FakeClock) -> None:
    big = {**BODY, "padding": "x" * 262_144}
    respx.get(CATALOG_URL).mock(return_value=_ok(big))
    with pytest.raises(CatalogUnavailableError):
        await _cache(clock).permissions_for(["ricotdin:member"])


@respx.mock
async def test_concurrent_single_flight(clock: FakeClock) -> None:
    route = respx.get(CATALOG_URL).mock(return_value=_ok())
    cache = _cache(clock)
    results = await asyncio.gather(*(cache.permissions_for(["ricotdin:member"]) for _ in range(10)))
    assert all(r == {"ricotdin:notes:read"} for r in results)
    assert route.call_count == 1


@respx.mock
async def test_contract_example_parses(clock: FakeClock) -> None:
    respx.get(CATALOG_URL).mock(
        return_value=httpx.Response(200, json=EXAMPLE["body"], headers=EXAMPLE["headers"])
    )
    cache = _cache(clock)
    assert await cache.permissions_for(["ricotdin:admin"]) == {"ricotdin:*"}
