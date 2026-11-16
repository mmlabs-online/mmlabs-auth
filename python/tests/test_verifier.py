import httpx
import pytest
import respx

from mmlabs_auth import AccessTokenVerifier, InvalidAccessTokenError, JwksCache
from tests.conftest import (
    AUDIENCE,
    ISSUER,
    JWKS_URL,
    SUB,
    UA,
    FakeClock,
    KeyPair,
    jwks_body,
    mint,
    new_key,
)


def _verifier(clock: FakeClock) -> AccessTokenVerifier:
    jwks = JwksCache(JWKS_URL, user_agent=UA, clock=clock)
    return AccessTokenVerifier(jwks, audience=AUDIENCE, issuer=ISSUER)


@respx.mock
async def test_async_verify_valid(clock: FakeClock, key: KeyPair) -> None:
    respx.get(JWKS_URL).respond(200, json=jwks_body(key))
    claims = await _verifier(clock).verify(mint(key))
    assert claims["sub"] == SUB


@respx.mock
async def test_unknown_kid_triggers_one_jwks_refetch(clock: FakeClock, key: KeyPair) -> None:
    route = respx.get(JWKS_URL).respond(200, json=jwks_body(key))
    verifier = _verifier(clock)
    await verifier.verify(mint(key))
    stranger = new_key()
    for _ in range(3):
        with pytest.raises(InvalidAccessTokenError) as exc_info:
            await verifier.verify(mint(stranger))
        assert exc_info.value.reason == "kid"
    assert route.call_count == 2


@respx.mock
async def test_jku_header_ignored_no_extra_request(clock: FakeClock, key: KeyPair) -> None:
    attacker = new_key()
    route = respx.get(JWKS_URL).respond(200, json=jwks_body(key))
    evil = respx.get("https://evil.invalid/jwks.json").respond(200, json=jwks_body(attacker))
    headers = {
        "kid": attacker.kid,
        "jku": "https://evil.invalid/jwks.json",
        "x5u": "https://evil.invalid/cert.pem",
        "jwk": attacker.jwk(),
    }
    with pytest.raises(InvalidAccessTokenError) as exc_info:
        await _verifier(clock).verify(mint(attacker, headers=headers))
    assert exc_info.value.reason == "kid"
    assert evil.call_count == 0
    assert route.call_count == 2  # initial fetch + one unknown-kid refetch


@respx.mock
async def test_bad_header_never_fetches(clock: FakeClock, key: KeyPair) -> None:
    route = respx.get(JWKS_URL).respond(200, json=jwks_body(key))
    verifier = _verifier(clock)
    for token, reason in [
        ("garbage", "malformed"),
        (mint(key, headers={"typ": "JWT"}), "typ"),
        (mint(key, headers={"kid": "k" * 129}), "kid"),
    ]:
        with pytest.raises(InvalidAccessTokenError) as exc_info:
            await verifier.verify(token)
        assert exc_info.value.reason == reason
    assert route.call_count == 0


@respx.mock
async def test_rotation_new_kid_after_flush(clock: FakeClock, key: KeyPair) -> None:
    rotated = new_key()
    route = respx.get(JWKS_URL).mock(
        side_effect=[
            httpx.Response(200, json=jwks_body(key)),
            httpx.Response(200, json=jwks_body(key)),
            httpx.Response(200, json=jwks_body(rotated)),
            httpx.Response(200, json=jwks_body(rotated)),
        ]
    )
    jwks = JwksCache(JWKS_URL, user_agent=UA, clock=clock)
    verifier = AccessTokenVerifier(jwks, audience=AUDIENCE, issuer=ISSUER)
    await verifier.verify(mint(key))
    with pytest.raises(InvalidAccessTokenError):  # not yet published: refetch, still unknown
        await verifier.verify(mint(rotated))
    with pytest.raises(InvalidAccessTokenError):  # cooldown: no fetch
        await verifier.verify(mint(rotated))
    assert route.call_count == 2
    jwks.flush()  # emergency rotation: the old key is gone at once
    assert (await verifier.verify(mint(rotated)))["sub"] == SUB
    with pytest.raises(InvalidAccessTokenError) as exc_info:
        await verifier.verify(mint(key))
    assert exc_info.value.reason == "kid"
    assert route.call_count == 4  # flush reset the cooldown: one refetch for the old kid


def test_leeway_over_30_raises_value_error() -> None:
    jwks = JwksCache(JWKS_URL, user_agent=UA)
    with pytest.raises(ValueError):
        AccessTokenVerifier(jwks, audience=AUDIENCE, issuer=ISSUER, leeway=31)
