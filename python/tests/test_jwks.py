import asyncio

import httpx
import pytest
import respx

from mmlabs_auth import JwksCache, JwksUnavailableError
from tests.conftest import DROP, JWKS_URL, UA, FakeClock, KeyPair, jwks_body, new_key


def _cache(clock: FakeClock) -> JwksCache:
    return JwksCache(JWKS_URL, user_agent=UA, clock=clock)


def _ok(*keys: KeyPair, max_age: int | None = 300, etag: str = '"e1"') -> httpx.Response:
    headers = {"ETag": etag}
    if max_age is not None:
        headers["Cache-Control"] = f"public, max-age={max_age}"
    return httpx.Response(200, json=jwks_body(*keys), headers=headers)


@respx.mock
async def test_fetch_and_select_by_kid(clock: FakeClock, key: KeyPair) -> None:
    other = new_key()
    route = respx.get(JWKS_URL).mock(return_value=_ok(key, other))
    cache = _cache(clock)
    keys = await cache.keys_for(key.kid)
    assert keys[key.kid].public_numbers() == key.public.public_numbers()
    assert set(keys) == {key.kid, other.kid}
    assert route.call_count == 1
    await cache.keys_for(other.kid)
    assert route.call_count == 1


@respx.mock
@pytest.mark.parametrize(("max_age", "ttl"), [(120, 120), (7200, 3600), (None, 300)])
async def test_ttl_from_max_age_capped_3600_default_300(
    clock: FakeClock, key: KeyPair, max_age: int | None, ttl: int
) -> None:
    route = respx.get(JWKS_URL).mock(return_value=_ok(key, max_age=max_age))
    cache = _cache(clock)
    await cache.keys()
    clock.advance(ttl - 1)
    await cache.keys()
    assert route.call_count == 1
    clock.advance(1)
    await cache.keys()
    assert route.call_count == 2


@respx.mock
async def test_304_keeps_keys_and_extends_ttl(clock: FakeClock, key: KeyPair) -> None:
    route = respx.get(JWKS_URL).mock(
        side_effect=[
            _ok(key),
            httpx.Response(304, headers={"ETag": '"e1"', "Cache-Control": "max-age=300"}),
        ]
    )
    cache = _cache(clock)
    await cache.keys()
    clock.advance(300)
    keys = await cache.keys()
    assert key.kid in keys
    assert route.call_count == 2
    assert route.calls.last.request.headers["If-None-Match"] == '"e1"'
    clock.advance(299)
    await cache.keys()
    assert route.call_count == 2


@respx.mock
async def test_unknown_kid_refetches_once(clock: FakeClock, key: KeyPair) -> None:
    rotated = new_key()
    route = respx.get(JWKS_URL).mock(side_effect=[_ok(key), _ok(key, rotated)])
    cache = _cache(clock)
    await cache.keys()
    keys = await cache.keys_for(rotated.kid)
    assert rotated.kid in keys
    assert route.call_count == 2


@respx.mock
async def test_second_unknown_kid_within_60s_no_fetch(clock: FakeClock, key: KeyPair) -> None:
    route = respx.get(JWKS_URL).mock(return_value=_ok(key))
    cache = _cache(clock)
    await cache.keys()
    assert "nope-1" not in await cache.keys_for("nope-1")
    assert route.call_count == 2
    clock.advance(59)
    assert "nope-2" not in await cache.keys_for("nope-2")
    assert route.call_count == 2


@respx.mock
async def test_unknown_kid_after_cooldown_refetches(clock: FakeClock, key: KeyPair) -> None:
    route = respx.get(JWKS_URL).mock(return_value=_ok(key))
    cache = _cache(clock)
    await cache.keys_for("nope-1")
    count = route.call_count
    clock.advance(60)
    await cache.keys_for("nope-2")
    assert route.call_count == count + 1


@respx.mock
async def test_cooldown_applies_after_failed_fetch(clock: FakeClock, key: KeyPair) -> None:
    route = respx.get(JWKS_URL).mock(side_effect=[_ok(key), httpx.Response(500)])
    cache = _cache(clock)
    await cache.keys()
    assert key.kid in await cache.keys_for("nope-1")  # fetch fails; stale keys kept
    assert route.call_count == 2
    clock.advance(30)
    await cache.keys_for("nope-2")
    assert route.call_count == 2


@respx.mock
async def test_concurrent_unknown_kid_single_fetch(clock: FakeClock, key: KeyPair) -> None:
    rotated = new_key()
    route = respx.get(JWKS_URL).mock(side_effect=[_ok(key), _ok(key, rotated)])
    cache = _cache(clock)
    await cache.keys()
    results = await asyncio.gather(*(cache.keys_for(rotated.kid) for _ in range(10)))
    assert all(rotated.kid in r for r in results)
    assert route.call_count == 2


@respx.mock
async def test_concurrent_cold_start_single_fetch(clock: FakeClock, key: KeyPair) -> None:
    route = respx.get(JWKS_URL).mock(return_value=_ok(key))
    cache = _cache(clock)
    await asyncio.gather(*(cache.keys_for(key.kid) for _ in range(10)))
    assert route.call_count == 1


@respx.mock
async def test_flush_drops_keys_and_resets_cooldown(clock: FakeClock, key: KeyPair) -> None:
    rotated = new_key()
    route = respx.get(JWKS_URL).mock(side_effect=[_ok(key), _ok(key), _ok(rotated)])
    cache = _cache(clock)
    await cache.keys_for("nope")  # initial fetch + unknown-kid refetch, cooldown now active
    assert route.call_count == 2
    cache.flush()
    keys = await cache.keys_for(rotated.kid)
    assert set(keys) == {rotated.kid}
    assert route.call_count == 3
    assert "If-None-Match" not in route.calls.last.request.headers


@respx.mock
async def test_non_es256_keys_filtered(clock: FakeClock, key: KeyPair) -> None:
    good = key.jwk()
    body = {
        "keys": [
            {"kty": "RSA", "kid": "rsa", "n": "AQAB", "e": "AQAB", "alg": "RS256"},
            new_key("p384").jwk(crv="P-384"),
            new_key("rs256").jwk(alg="RS256"),
            new_key("es384").jwk(alg="ES384"),
            new_key("enc").jwk(use="enc"),
            new_key("private").jwk(d="AAAA"),
            new_key("noalg").jwk(alg=DROP, use=DROP),
            new_key("badx").jwk(x="AAAA"),
            new_key("offcurve").jwk(y=good["x"]),
            {"kty": "EC", "crv": "P-256", "x": good["x"], "y": good["y"], "kid": 7},
            "not-a-dict",
            good,
        ]
    }
    respx.get(JWKS_URL).respond(200, json=body)
    keys = await _cache(clock).keys()
    assert set(keys) == {key.kid, "noalg"}


@respx.mock
async def test_fetch_error_serves_stale_until_max_ttl_then_fails_closed(
    clock: FakeClock, key: KeyPair
) -> None:
    route = respx.get(JWKS_URL).mock(return_value=_ok(key))
    cache = _cache(clock)
    await cache.keys()
    route.mock(return_value=httpx.Response(503))
    clock.advance(300)
    assert key.kid in await cache.keys()
    clock.advance(3299)
    assert key.kid in await cache.keys()
    clock.advance(1)
    with pytest.raises(JwksUnavailableError):
        await cache.keys()
    with pytest.raises(JwksUnavailableError):
        await cache.keys_for(key.kid)


@respx.mock
async def test_failed_refresh_not_retried_before_cooldown(clock: FakeClock, key: KeyPair) -> None:
    route = respx.get(JWKS_URL).mock(return_value=_ok(key))
    cache = _cache(clock)
    await cache.keys()
    route.mock(return_value=httpx.Response(503))
    clock.advance(300)
    await cache.keys()
    await cache.keys()
    assert route.call_count == 2
    clock.advance(60)
    await cache.keys()
    assert route.call_count == 3


@respx.mock
async def test_timeout_without_cache_fails_closed(clock: FakeClock) -> None:
    respx.get(JWKS_URL).mock(side_effect=httpx.ConnectTimeout)
    with pytest.raises(JwksUnavailableError) as exc_info:
        await _cache(clock).keys_for("any")
    assert JWKS_URL not in str(exc_info.value)


@respx.mock
@pytest.mark.parametrize(
    "content", [b"not json", b"[]", b'{"keys": "x"}', b'{"keys": []}'], ids=str
)
async def test_invalid_json_fails_closed(clock: FakeClock, content: bytes) -> None:
    respx.get(JWKS_URL).respond(200, content=content)
    with pytest.raises(JwksUnavailableError):
        await _cache(clock).keys()


def test_http_url_refused() -> None:
    with pytest.raises(ValueError):
        JwksCache("http://api.mmlabs.online/.well-known/jwks.json", user_agent=UA)
    JwksCache(
        "http://localhost:8000/.well-known/jwks.json", user_agent=UA, allow_insecure_loopback=True
    )
