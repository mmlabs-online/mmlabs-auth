"""Async access-token verification: the JWKS cache plus the pure `verify_access_token`."""

from collections.abc import Mapping
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from mmlabs_auth.access_token import (
    ALGORITHM,
    MAX_KID_LENGTH,
    MAX_LEEWAY,
    TOKEN_TYP,
    InvalidAccessTokenError,
    verify_access_token,
)
from mmlabs_auth.jwks import JwksCache


class AccessTokenVerifier:
    """Only the header `kid` selects a key. `jku`, `x5u` and `jwk` headers are never read."""

    def __init__(self, jwks: JwksCache, *, audience: str, issuer: str, leeway: int = 30) -> None:
        if leeway > MAX_LEEWAY:
            raise ValueError("leeway must be at most 30 seconds")
        self._jwks = jwks
        self._audience = audience
        self._issuer = issuer
        self._leeway = leeway

    async def verify(self, token: str) -> dict[str, Any]:
        """The verified claims, or `InvalidAccessTokenError`. May raise `JwksUnavailableError`."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            raise InvalidAccessTokenError("malformed") from None
        kid = header.get("kid")
        keys: Mapping[str, EllipticCurvePublicKey] = {}
        # A header that fails anyway never triggers a JWKS fetch.
        if (
            header.get("typ") == TOKEN_TYP
            and header.get("alg") == ALGORITHM
            and isinstance(kid, str)
            and len(kid) <= MAX_KID_LENGTH
        ):
            keys = await self._jwks.keys_for(kid)
        return verify_access_token(
            token, keys, audience=self._audience, issuer=self._issuer, leeway=self._leeway
        )
