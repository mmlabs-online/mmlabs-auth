"""Access-token verification (ADR-0005, ADR-0008): the checks `docs/consumers.md` prescribes.

Verbatim copy of org-admin-api `app/core/access_token.py` (commit in `contract/SOURCE`), with
only these changes: `keys` is a `kid -> public key` mapping instead of a `KeySet`;
`ALGORITHM`/`TOKEN_TYP` are local constants; `leeway > 30` raises `ValueError`; a `kid` longer
than 128 characters fails with reason `kid`. `tests/test_drift.py` compares the two.

Pure (no ORM, no FastAPI). Every failure raises `InvalidAccessTokenError` with a fixed reason
code; the token never appears in it (R11).
"""

from collections.abc import Mapping
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

ALGORITHM = "ES256"
TOKEN_TYP = "at+jwt"  # noqa: S105 - JWT header type, not a secret
MAX_LEEWAY = 30
MAX_KID_LENGTH = 128

REQUIRED_CLAIMS = ["exp", "iat", "sub", "jti", "iss", "aud"]


class InvalidAccessTokenError(Exception):
    """`reason` is one of: malformed, typ, alg, kid, signature, expired, audience, issuer,
    claims, email_verified. For logs only, never for responses."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason

    def __repr__(self) -> str:
        return f"InvalidAccessTokenError({self.reason!r})"


def verify_access_token(
    token: str,
    keys: Mapping[str, EllipticCurvePublicKey],
    *,
    audience: str,
    issuer: str,
    leeway: int = 30,
) -> dict[str, Any]:
    """The verified claims, or `InvalidAccessTokenError`. `aud` must be a string equal to
    `audience`; a list (even `["admin"]`) fails with reason `audience` (`strict_aud`)."""
    if leeway > MAX_LEEWAY:
        raise ValueError("leeway must be at most 30 seconds")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError:
        raise InvalidAccessTokenError("malformed") from None
    if header.get("typ") != TOKEN_TYP:
        raise InvalidAccessTokenError("typ")
    if header.get("alg") != ALGORITHM:
        raise InvalidAccessTokenError("alg")
    kid = header.get("kid")
    if not isinstance(kid, str) or len(kid) > MAX_KID_LENGTH or kid not in keys:
        raise InvalidAccessTokenError("kid")
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            keys[kid],
            algorithms=[ALGORITHM],
            audience=audience,
            issuer=issuer,
            leeway=leeway,
            options={"require": REQUIRED_CLAIMS, "strict_aud": True},
        )
    except jwt.ExpiredSignatureError:
        raise InvalidAccessTokenError("expired") from None
    except jwt.InvalidSignatureError:
        raise InvalidAccessTokenError("signature") from None
    except jwt.InvalidAudienceError:
        raise InvalidAccessTokenError("audience") from None
    except jwt.InvalidIssuerError:
        raise InvalidAccessTokenError("issuer") from None
    except jwt.DecodeError:
        raise InvalidAccessTokenError("malformed") from None
    except jwt.InvalidTokenError:  # missing claim, future `iat`, bad claim types
        raise InvalidAccessTokenError("claims") from None
    if claims.get("email_verified") is not True:
        raise InvalidAccessTokenError("email_verified")
    return claims
