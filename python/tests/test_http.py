import asyncio
from collections.abc import AsyncIterator

import httpx
import pytest
import respx

from mmlabs_auth import _http
from mmlabs_auth._http import FetchError, check_url, fetch_json, new_client
from tests.conftest import JWKS_URL, UA


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with new_client(UA) as c:
        yield c


@pytest.mark.parametrize(
    "url", ["http://api.mmlabs.online/x", "ftp://api.mmlabs.online/x", "https:///x"]
)
async def test_http_url_refused(client: httpx.AsyncClient, url: str) -> None:
    with pytest.raises(ValueError):
        check_url(url)
    with pytest.raises(ValueError):
        await fetch_json(client, url, etag=None, max_bytes=100)


def test_loopback_http_only_with_flag() -> None:
    for url in ("http://localhost:8000/x", "http://127.0.0.1/x", "http://[::1]/x"):
        with pytest.raises(ValueError):
            check_url(url)
        check_url(url, allow_insecure_loopback=True)
    with pytest.raises(ValueError):
        check_url("http://api.mmlabs.online/x", allow_insecure_loopback=True)
    with pytest.raises(ValueError):
        check_url("http://localhost.evil.invalid/x", allow_insecure_loopback=True)


@respx.mock
async def test_redirect_not_followed(client: httpx.AsyncClient) -> None:
    route = respx.get(JWKS_URL).respond(302, headers={"Location": "https://evil.invalid/jwks"})
    evil = respx.get("https://evil.invalid/jwks").respond(200, json={"keys": []})
    with pytest.raises(FetchError) as exc_info:
        await fetch_json(client, JWKS_URL, etag=None, max_bytes=100)
    assert exc_info.value.reason == "redirect"
    assert route.call_count == 1
    assert evil.call_count == 0


@respx.mock
@pytest.mark.parametrize("exc", [httpx.ConnectTimeout, httpx.ReadTimeout])
async def test_timeout_raises(client: httpx.AsyncClient, exc: type[Exception]) -> None:
    respx.get(JWKS_URL).mock(side_effect=exc)
    with pytest.raises(FetchError) as exc_info:
        await fetch_json(client, JWKS_URL, etag=None, max_bytes=100)
    assert exc_info.value.reason == "timeout"


@respx.mock
async def test_total_timeout_raises(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_http, "TOTAL_TIMEOUT", 0.05)

    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(1)
        return httpx.Response(200, json={})

    respx.get(JWKS_URL).mock(side_effect=slow)
    with pytest.raises(FetchError) as exc_info:
        await fetch_json(client, JWKS_URL, etag=None, max_bytes=100)
    assert exc_info.value.reason == "timeout"


def test_client_timeouts() -> None:
    timeout = new_client(UA).timeout
    assert timeout.connect == 3.0
    assert timeout.read == 5.0


@respx.mock
async def test_body_over_cap_rejected(client: httpx.AsyncClient) -> None:
    respx.get(JWKS_URL).respond(200, content=b'{"a":"' + b"x" * 200 + b'"}')
    with pytest.raises(FetchError) as exc_info:
        await fetch_json(client, JWKS_URL, etag=None, max_bytes=100)
    assert exc_info.value.reason == "too_large"


@respx.mock
async def test_body_over_cap_rejected_without_content_length(client: httpx.AsyncClient) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(10):
            yield b"x" * 50

    respx.get(JWKS_URL).respond(200, stream=chunks())  # type: ignore[arg-type]
    with pytest.raises(FetchError) as exc_info:
        await fetch_json(client, JWKS_URL, etag=None, max_bytes=100)
    assert exc_info.value.reason == "too_large"


@respx.mock
async def test_sends_user_agent_and_if_none_match(client: httpx.AsyncClient) -> None:
    route = respx.get(JWKS_URL).respond(
        200, json={"ok": True}, headers={"ETag": '"v2"', "Cache-Control": "public, max-age=300"}
    )
    result = await fetch_json(client, JWKS_URL, etag='"v1"', max_bytes=100)
    request = route.calls.last.request
    assert request.headers["User-Agent"] == UA
    assert request.headers["If-None-Match"] == '"v1"'
    assert result == _http.FetchResult(200, {"ok": True}, '"v2"', 300)


@respx.mock
async def test_invalid_json_raises(client: httpx.AsyncClient) -> None:
    respx.get(JWKS_URL).respond(200, content=b"not json")
    with pytest.raises(FetchError) as exc_info:
        await fetch_json(client, JWKS_URL, etag=None, max_bytes=100)
    assert exc_info.value.reason == "invalid_json"


@respx.mock
async def test_accept_encoding_identity_sent(client: httpx.AsyncClient) -> None:
    route = respx.get(JWKS_URL).respond(200, json={})
    await fetch_json(client, JWKS_URL, etag=None, max_bytes=100)
    assert route.calls.last.request.headers["accept-encoding"] == "identity"


@respx.mock
async def test_deeply_nested_json_is_invalid_json(client: httpx.AsyncClient) -> None:
    respx.get(JWKS_URL).respond(200, content=b"[" * 60000)
    with pytest.raises(FetchError) as exc_info:
        await fetch_json(client, JWKS_URL, etag=None, max_bytes=100_000)
    assert exc_info.value.reason == "invalid_json"
