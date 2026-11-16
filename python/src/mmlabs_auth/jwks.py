"""Async JWKS cache keyed by `kid` (USR-03c S1/S2).

- TTL from `Cache-Control: max-age`, floored at 30 s, capped at `max_ttl` (1 h);
  `default_ttl` (300 s) without it.
  Revalidation sends `If-None-Match`; a 304 keeps the keys and extends the TTL.
- An unknown `kid` refetches at most once per `cooldown` (60 s), also after a failed fetch.
  A failed refresh is not retried before `cooldown` either.
- One fetch at a time (`asyncio.Lock`); waiters re-check after acquiring it.
- Only EC P-256 keys for ES256 signatures (`alg` ES256 or absent, `use` sig or absent).
- After a failed fetch the last good keys are served until `max_ttl` after the last successful
  fetch; then `JwksUnavailableError` (fail closed).
- `flush()` drops everything (emergency key rotation).
"""

import asyncio
import base64
import binascii
import time
from collections.abc import Callable, Mapping
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from mmlabs_auth._http import FetchError, check_url, fetch_json, new_client
from mmlabs_auth.access_token import MAX_KID_LENGTH
from mmlabs_auth.errors import JwksUnavailableError

JWKS_MAX_BYTES = 65_536
MIN_TTL = 30.0  # floor: `max-age=0` must not cause a refetch on every verification
_COORD_BYTES = 32


def _b64url(value: object) -> bytes | None:
    if not isinstance(value, str):
        return None
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return None


def _parse_jwk(jwk: object) -> tuple[str, ec.EllipticCurvePublicKey] | None:
    if not isinstance(jwk, dict):
        return None
    kid = jwk.get("kid")
    if not isinstance(kid, str) or not kid or len(kid) > MAX_KID_LENGTH:
        return None
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" in jwk:
        return None
    if jwk.get("alg", "ES256") != "ES256" or jwk.get("use", "sig") != "sig":
        return None
    x, y = _b64url(jwk.get("x")), _b64url(jwk.get("y"))
    if x is None or y is None or len(x) != _COORD_BYTES or len(y) != _COORD_BYTES:
        return None
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
    )
    try:
        return kid, numbers.public_key()
    except ValueError:  # not on the curve
        return None


def _parse_jwks(body: Any) -> dict[str, ec.EllipticCurvePublicKey] | None:
    if not isinstance(body, dict) or not isinstance(body.get("keys"), list):
        return None
    keys: dict[str, ec.EllipticCurvePublicKey] = {}
    for jwk in body["keys"]:
        parsed = _parse_jwk(jwk)
        if parsed is not None and parsed[0] not in keys:
            keys[parsed[0]] = parsed[1]
    return keys or None


class JwksCache:
    def __init__(
        self,
        url: str,
        *,
        user_agent: str,
        default_ttl: float = 300,
        max_ttl: float = 3600,
        cooldown: float = 60,
        allow_insecure_loopback: bool = False,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        check_url(url, allow_insecure_loopback=allow_insecure_loopback)
        self._url = url
        self._allow_insecure_loopback = allow_insecure_loopback
        self._default_ttl = default_ttl
        self._max_ttl = max_ttl
        self._cooldown = cooldown
        self._clock = clock
        self._client = new_client(user_agent)
        self._lock = asyncio.Lock()
        self._generation = 0
        self.flush()

    def flush(self) -> None:
        """Drop keys, ETag and every cooldown; the next call fetches."""
        self._generation += 1
        self._keys: dict[str, ec.EllipticCurvePublicKey] = {}
        self._etag: str | None = None
        self._ok_at: float | None = None  # last 200 or 304
        self._fresh_until = 0.0
        self._retry_at = 0.0  # no refresh before this (after a failure)
        self._kid_retry_at = 0.0  # no unknown-kid refetch before this

    async def keys(self) -> Mapping[str, ec.EllipticCurvePublicKey]:
        """The current keys, refreshed when the TTL has passed."""
        if self._ok_at is not None and self._clock() < self._fresh_until:
            return self._keys
        async with self._lock:
            now = self._clock()
            if (self._ok_at is None or now >= self._fresh_until) and now >= self._retry_at:
                await self._refresh()
            return self._usable()

    async def keys_for(self, kid: str) -> Mapping[str, ec.EllipticCurvePublicKey]:
        """`keys()`, refetched first when `kid` is unknown and the cooldown has passed. The
        result may still lack `kid`; the verifier then fails with reason `kid`."""
        keys = await self.keys()
        if kid in keys or self._clock() < self._kid_retry_at:
            return keys
        async with self._lock:
            now = self._clock()
            if kid not in self._keys and now >= self._kid_retry_at:
                self._kid_retry_at = now + self._cooldown
                await self._refresh()
            return self._usable()

    async def aclose(self) -> None:
        await self._client.aclose()

    def _usable(self) -> Mapping[str, ec.EllipticCurvePublicKey]:
        if self._ok_at is None or self._clock() >= self._ok_at + self._max_ttl:
            raise JwksUnavailableError()
        return self._keys

    async def _refresh(self) -> None:
        generation = self._generation
        try:
            result = await fetch_json(
                self._client,
                self._url,
                etag=self._etag if self._keys else None,
                max_bytes=JWKS_MAX_BYTES,
                allow_insecure_loopback=self._allow_insecure_loopback,
            )
            keys = _parse_jwks(result.body) if result.status == 200 else None
            if result.status == 200:
                ok = keys is not None
            else:
                ok = result.status == 304 and bool(self._keys)
            if not ok:
                raise FetchError("response")
        except FetchError:
            if generation == self._generation:
                self._retry_at = self._clock() + self._cooldown
            return
        if generation != self._generation:  # flushed while fetching
            return
        now = self._clock()
        if keys is not None:
            self._keys = keys
        self._etag = result.etag
        self._ok_at = now
        ttl = self._default_ttl if result.max_age is None else result.max_age
        self._fresh_until = now + min(max(float(ttl), MIN_TTL), self._max_ttl)
