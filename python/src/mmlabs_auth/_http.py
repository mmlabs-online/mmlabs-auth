"""Shared HTTP fetch for the JWKS and role-catalog caches.

HTTPS only (loopback `http` only when explicitly allowed), never follows redirects,
3 s connect / 5 s total, a byte cap on the body, `User-Agent` and `If-None-Match`.
"""

import asyncio
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

CONNECT_TIMEOUT = 3.0
TOTAL_TIMEOUT = 5.0
_MAX_AGE_RE = re.compile(r"(?:^|,)\s*max-age\s*=\s*(\d{1,10})\s*(?:,|$)", re.IGNORECASE)


class FetchError(Exception):
    """A failed fetch. `reason` is a fixed code; no URL, body or header value is kept."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class FetchResult:
    status: int
    body: Any | None
    etag: str | None
    max_age: int | None


def _is_loopback(host: str | None) -> bool:
    if host is None:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_url(url: str, *, allow_insecure_loopback: bool = False) -> None:
    """`ValueError` unless `url` is `https://`, or loopback `http://` with the opt-in."""
    parts = urlsplit(url)
    if not parts.hostname:
        raise ValueError("mmlabs-auth: URL must have a host")
    if parts.scheme == "https":
        return
    if parts.scheme == "http" and allow_insecure_loopback and _is_loopback(parts.hostname):
        return
    raise ValueError("mmlabs-auth: URL must use https")


def new_client(user_agent: str) -> httpx.AsyncClient:
    """TLS verification on, no redirects, fixed timeouts. Not configurable by callers."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(TOTAL_TIMEOUT, connect=CONNECT_TIMEOUT),
        follow_redirects=False,
        verify=True,
        headers={"User-Agent": user_agent},
    )


def _max_age(response: httpx.Response) -> int | None:
    match = _MAX_AGE_RE.search(response.headers.get("cache-control", ""))
    return int(match.group(1)) if match else None


async def fetch_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    etag: str | None,
    max_bytes: int,
    allow_insecure_loopback: bool = False,
) -> FetchResult:
    """200 → parsed JSON body; 304 → no body; any other non-3xx status → no body (the caller
    decides). Raises `FetchError` on a redirect, network error, timeout, oversize or bad JSON."""
    check_url(url, allow_insecure_loopback=allow_insecure_loopback)
    headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
    if etag is not None:
        headers["If-None-Match"] = etag
    try:
        async with asyncio.timeout(TOTAL_TIMEOUT):
            async with client.stream("GET", url, headers=headers, follow_redirects=False) as resp:
                status = resp.status_code
                if status == 304:
                    return FetchResult(304, None, resp.headers.get("etag") or etag, _max_age(resp))
                if 300 <= status < 400:
                    raise FetchError("redirect")
                if status != 200:
                    return FetchResult(status, None, None, None)
                declared = resp.headers.get("content-length")
                if declared is not None and declared.isdigit() and int(declared) > max_bytes:
                    raise FetchError("too_large")
                body = bytearray()
                async for chunk in resp.aiter_bytes():
                    body += chunk
                    if len(body) > max_bytes:
                        raise FetchError("too_large")
                new_etag = resp.headers.get("etag")
                max_age = _max_age(resp)
    except TimeoutError:
        raise FetchError("timeout") from None
    except httpx.TimeoutException:
        raise FetchError("timeout") from None
    except httpx.HTTPError:
        raise FetchError("network") from None
    try:
        parsed = json.loads(bytes(body))
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise FetchError("invalid_json") from None
    return FetchResult(200, parsed, new_etag, max_age)
