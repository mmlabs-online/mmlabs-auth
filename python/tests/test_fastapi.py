import logging
import time
from collections.abc import AsyncIterator, Iterator
from typing import Annotated, Any

import httpx
import pytest
import respx
from fastapi import Depends, FastAPI

from mmlabs_auth.fastapi import MmlabsAuth, Principal, register_exception_handler
from tests.conftest import (
    AUDIENCE,
    CATALOG_URL,
    JWKS_URL,
    SUB,
    UA,
    KeyPair,
    jwks_body,
    mint,
)

CATALOG = {
    "app": "ricotdin",
    "roles": [
        {"key": "ricotdin:admin", "permissions": ["ricotdin:*"]},
        {"key": "ricotdin:member", "permissions": ["ricotdin:notes:read"]},
    ],
}


def _app(auth: MmlabsAuth, *, handler: bool = True) -> FastAPI:
    app = FastAPI()
    if handler:
        register_exception_handler(app)

    @app.get("/notes")
    async def read(
        p: Annotated[Principal, Depends(auth.require_permission("ricotdin:notes:read"))],
    ) -> dict[str, Any]:
        return {"sub": p.sub, "roles": list(p.roles), "jti": p.jti}

    @app.post("/notes")
    async def write(
        p: Annotated[Principal, Depends(auth.require_permission("ricotdin:notes:write"))],
    ) -> dict[str, Any]:
        return {"sub": p.sub}

    return app


@pytest.fixture
def mocked(key: KeyPair) -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        router.get(JWKS_URL).respond(200, json=jwks_body(key))
        router.get(CATALOG_URL).respond(200, json=CATALOG, headers={"ETag": '"c1"'})
        yield router


@pytest.fixture
async def client(mocked: respx.MockRouter) -> AsyncIterator[httpx.AsyncClient]:
    auth = MmlabsAuth(audience=AUDIENCE, user_agent=UA)
    transport = httpx.ASGITransport(app=_app(auth))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c
    await auth.aclose()


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _assert_401(resp: httpx.Response, challenge: str) -> None:
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == challenge
    assert resp.json() == {
        "error": {"code": "unauthorized", "message": "Authentication required", "details": None}
    }


async def test_valid_token_with_permission_returns_principal(
    client: httpx.AsyncClient, key: KeyPair
) -> None:
    resp = await client.get("/notes", headers=_bearer(mint(key, jti="j-1")))
    assert resp.status_code == 200
    assert resp.json() == {"sub": SUB, "roles": ["ricotdin:member"], "jti": "j-1"}
    resp = await client.get("/notes", headers={"Authorization": f"bearer {mint(key)}"})
    assert resp.status_code == 200


@pytest.mark.parametrize(
    "headers", [{}, {"Authorization": "Basic dXNlcjpwdw=="}, {"Authorization": "Bearer"}]
)
async def test_missing_header_401_bearer_challenge_envelope(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    _assert_401(await client.get("/notes", headers=headers), "Bearer")


async def test_invalid_token_401_invalid_token_no_reason_in_body(
    client: httpx.AsyncClient, key: KeyPair
) -> None:
    resp = await client.get("/notes", headers=_bearer(mint(key, email_verified=False)))
    _assert_401(resp, 'Bearer error="invalid_token"')
    assert "email_verified" not in resp.text
    _assert_401(
        await client.get("/notes", headers=_bearer("garbage")), 'Bearer error="invalid_token"'
    )


async def test_expired_and_wrong_aud_401(client: httpx.AsyncClient, key: KeyPair) -> None:
    now = int(time.time())
    for token in (mint(key, iat=now - 1000, exp=now - 60), mint(key, aud="stoktok")):
        _assert_401(
            await client.get("/notes", headers=_bearer(token)), 'Bearer error="invalid_token"'
        )


async def test_missing_permission_403_permission_denied_details_required(
    client: httpx.AsyncClient, key: KeyPair
) -> None:
    resp = await client.post("/notes", headers=_bearer(mint(key)))
    assert resp.status_code == 403
    assert resp.json() == {
        "error": {
            "code": "permission_denied",
            "message": "Missing permission",
            "details": {"required": "ricotdin:notes:write"},
        }
    }
    for roles in ([], "ricotdin:admin", ["ricotdin:ghost", 7]):
        resp = await client.post("/notes", headers=_bearer(mint(key, roles=roles)))
        assert resp.status_code == 403


async def test_wildcard_role_permits(client: httpx.AsyncClient, key: KeyPair) -> None:
    resp = await client.post("/notes", headers=_bearer(mint(key, roles=["ricotdin:admin"])))
    assert resp.status_code == 200


@pytest.mark.parametrize(
    "perm", ["stoktok:notes:read", "ricotdin", "ricotdin:notes", "*", "ricotdin:notes:*", "admin:*"]
)
def test_permission_prefix_mismatch_raises_at_definition(perm: str) -> None:
    auth = MmlabsAuth(audience=AUDIENCE, user_agent=UA)
    with pytest.raises(ValueError):
        auth.require_permission(perm)
    auth.require_permission("ricotdin:*")


def test_admin_audience_refused_at_construction() -> None:
    with pytest.raises(ValueError):
        MmlabsAuth(audience="admin", user_agent=UA)


@pytest.mark.parametrize("down", ["jwks", "catalog-503", "catalog-404"])
async def test_jwks_or_catalog_unavailable_503_auth_unavailable(
    client: httpx.AsyncClient, mocked: respx.MockRouter, key: KeyPair, down: str
) -> None:
    if down == "jwks":
        mocked.get(JWKS_URL).mock(side_effect=httpx.ConnectTimeout("t"))
    else:
        mocked.get(CATALOG_URL).respond(503 if down == "catalog-503" else 404)
    resp = await client.get("/notes", headers=_bearer(mint(key)))
    assert resp.status_code == 503
    assert resp.json() == {
        "error": {
            "code": "auth_unavailable",
            "message": "Authentication temporarily unavailable",
            "details": None,
        }
    }


async def test_logs_reason_without_token_or_email(
    client: httpx.AsyncClient, key: KeyPair, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    bad = mint(key, aud="stoktok")
    good = mint(key, jti="jti-42")
    await client.get("/notes", headers=_bearer(bad))
    await client.post("/notes", headers=_bearer(good))
    text = caplog.text
    assert "reason=audience" in text
    assert "jti=jti-42" in text
    for token in (bad, good):
        for part in token.split("."):
            assert part not in text
    assert "someone@example.com" not in text


async def test_status_correct_without_exception_handler(
    mocked: respx.MockRouter, key: KeyPair
) -> None:
    auth = MmlabsAuth(audience=AUDIENCE, user_agent=UA)
    transport = httpx.ASGITransport(app=_app(auth, handler=False))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        resp = await c.get("/notes")
        assert resp.status_code == 401
        assert resp.headers["WWW-Authenticate"] == "Bearer"
        assert (await c.post("/notes", headers=_bearer(mint(key)))).status_code == 403
    await auth.aclose()


def test_principal_repr_has_no_email_or_claims() -> None:
    p = Principal(
        sub=SUB,
        email="someone@example.com",
        roles=("ricotdin:member",),
        permissions=frozenset(),
        jti="j",
        claims={"email": "someone@example.com"},
    )
    assert "someone@example.com" not in repr(p)
