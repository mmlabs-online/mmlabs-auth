"""Test helpers: ephemeral P-256 keys (generated per run, never committed), token minting,
JWKS bodies and a fake monotonic clock."""

import base64
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

ISSUER = "https://api.mmlabs.online"
AUDIENCE = "ricotdin"
JWKS_URL = "https://api.mmlabs.online/.well-known/jwks.json"
CATALOG_URL = "https://api.mmlabs.online/api/v1/apps/ricotdin/roles"
UA = "mmlabs-auth-tests/0.1"
SUB = "3f1c2b8e-0000-4000-8000-000000000001"
DROP = object()  # remove a claim / header


def _b64(n: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode()


@dataclass
class KeyPair:
    kid: str
    private: ec.EllipticCurvePrivateKey = field(repr=False)

    @property
    def public(self) -> ec.EllipticCurvePublicKey:
        return self.private.public_key()

    def jwk(self, **overrides: Any) -> dict[str, Any]:
        numbers = self.public.public_numbers()
        jwk: dict[str, Any] = {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64(numbers.x),
            "y": _b64(numbers.y),
            "kid": self.kid,
            "alg": "ES256",
            "use": "sig",
        }
        jwk.update(overrides)
        return {k: v for k, v in jwk.items() if v is not DROP}


def new_key(kid: str | None = None) -> KeyPair:
    return KeyPair(kid or f"k-{uuid.uuid4().hex[:12]}", ec.generate_private_key(ec.SECP256R1()))


def jwks_body(*keys: KeyPair) -> dict[str, Any]:
    return {"keys": [k.jwk() for k in keys]}


def claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    base: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": SUB,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + 900,
        "email": "someone@example.com",
        "email_verified": True,
        "roles": ["ricotdin:member"],
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not DROP}


def mint(key: KeyPair, *, headers: dict[str, Any] | None = None, **claim_overrides: Any) -> str:
    hdr: dict[str, Any] = {"kid": key.kid, "typ": "at+jwt"}
    hdr.update(headers or {})
    hdr = {k: v for k, v in hdr.items() if v is not DROP}
    return jwt.encode(claims(**claim_overrides), key.private, algorithm="ES256", headers=hdr)


def mint_raw(key: KeyPair, header: dict[str, Any], **claim_overrides: Any) -> str:
    """ES256-signed by hand, so headers PyJWT refuses to encode (a non-string `kid`) work."""
    segments = [
        base64.urlsafe_b64encode(json.dumps(part).encode()).rstrip(b"=")
        for part in (header, claims(**claim_overrides))
    ]
    signing_input = b".".join(segments)
    signature = ECAlgorithm(ECAlgorithm.SHA256).sign(signing_input, key.private)
    return b".".join([signing_input, base64.urlsafe_b64encode(signature).rstrip(b"=")]).decode()


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def key() -> KeyPair:
    return new_key()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()
