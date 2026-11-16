"""The pure verifier; reasons match org-admin-api tests/test_access_token.py."""

import base64
import hashlib
import hmac
import json
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mmlabs_auth import InvalidAccessTokenError, verify_access_token
from tests.conftest import (
    AUDIENCE,
    DROP,
    ISSUER,
    SUB,
    KeyPair,
    claims,
    mint,
    mint_raw,
    new_key,
)


def _keys(key: KeyPair) -> dict[str, ec.EllipticCurvePublicKey]:
    return {key.kid: key.public}


def _verify(token: str, key: KeyPair, **kwargs: Any) -> dict[str, Any]:
    return verify_access_token(token, _keys(key), audience=AUDIENCE, issuer=ISSUER, **kwargs)


def _reason(token: str, key: KeyPair) -> str:
    with pytest.raises(InvalidAccessTokenError) as exc_info:
        _verify(token, key)
    return exc_info.value.reason


def _raw(key: KeyPair, headers: dict[str, Any], signing_key: Any, alg: str) -> str:
    hdr = {k: v for k, v in headers.items() if v is not DROP}
    return jwt.encode(claims(), signing_key, algorithm=alg, headers=hdr)


def test_valid_token_returns_claims(key: KeyPair) -> None:
    result = _verify(mint(key), key)
    assert result["sub"] == SUB
    assert result["aud"] == AUDIENCE


def test_expired_reason_expired(key: KeyPair) -> None:
    now = int(time.time())
    assert _reason(mint(key, iat=now - 1000, exp=now - 31), key) == "expired"


def test_within_leeway_accepted(key: KeyPair) -> None:
    now = int(time.time())
    assert _verify(mint(key, iat=now - 1000, exp=now - 10), key)["sub"] == SUB


@pytest.mark.parametrize("aud", ["stoktok", ["stoktok"]])
def test_wrong_audience_reason_audience(key: KeyPair, aud: object) -> None:
    assert _reason(mint(key, aud=aud), key) == "audience"


@pytest.mark.parametrize("aud", [[AUDIENCE], ["stoktok", AUDIENCE]])
def test_list_audience_reason_audience(key: KeyPair, aud: list[str]) -> None:
    assert _reason(mint(key, aud=aud), key) == "audience"


def test_wrong_issuer_reason_issuer(key: KeyPair) -> None:
    assert _reason(mint(key, iss="https://evil.invalid"), key) == "issuer"


@pytest.mark.parametrize("iss", ["https://api.mmlabs", "api.mmlabs.online", "https://api.mmlab"])
def test_issuer_prefix_reason_issuer(key: KeyPair, iss: str) -> None:
    # CVE-2024-53861: a substring of the issuer must not match.
    assert _reason(mint(key, iss=iss), key) == "issuer"


def test_alg_none_rejected(key: KeyPair) -> None:
    token = _raw(key, {"kid": key.kid, "typ": "at+jwt"}, None, "none")
    assert _reason(token, key) == "alg"


def test_alg_hs256_rejected(key: KeyPair) -> None:
    pem = key.public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # PyJWT refuses a PEM as an HMAC secret, so sign the HS256 token by hand.
    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "kid": key.kid, "typ": "at+jwt"}).encode())
    payload = b64(json.dumps(claims()).encode())
    sig = b64(hmac.new(pem, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    assert _reason(f"{header}.{payload}.{sig}", key) == "alg"


def test_alg_es384_rejected(key: KeyPair) -> None:
    p384 = ec.generate_private_key(ec.SECP384R1())
    token = _raw(key, {"kid": key.kid, "typ": "at+jwt"}, p384, "ES384")
    assert _reason(token, key) == "alg"


@pytest.mark.parametrize("typ", ["JWT", "at+JWT ", DROP], ids=["JWT", "near", "missing"])
def test_wrong_or_missing_typ_reason_typ(key: KeyPair, typ: object) -> None:
    assert _reason(mint(key, headers={"typ": typ}), key) == "typ"


def test_unknown_kid_reason_kid(key: KeyPair) -> None:
    assert _reason(mint(key, headers={"kid": "unknown"}), key) == "kid"
    assert _reason(mint(key, headers={"kid": DROP}), key) == "kid"


def test_non_string_or_long_kid_reason_kid() -> None:
    long_key = new_key("k" * 129)
    # Even when the long kid is present in the key map, it is refused.
    assert _reason(mint(long_key), long_key) == "kid"


@pytest.mark.parametrize("kid", [123, ["k"]], ids=["int", "list"])
def test_non_string_kid_reason_malformed(key: KeyPair, kid: object) -> None:
    # PyJWT's `get_unverified_header` already rejects a non-string `kid`, so the verbatim code
    # reports `malformed` (as the server does) before its own `kid` check.
    token = mint_raw(key, {"alg": "ES256", "typ": "at+jwt", "kid": kid})
    assert _reason(token, key) == "malformed"


def test_kid_of_128_chars_accepted() -> None:
    key = new_key("k" * 128)
    assert _verify(mint(key), key)["sub"] == SUB


def test_bad_signature_reason_signature(key: KeyPair) -> None:
    other = new_key(key.kid)
    assert _reason(mint(other), key) == "signature"


@pytest.mark.parametrize("claim", ["exp", "iat", "sub", "jti", "iss", "aud"])
def test_missing_claim_reason_claims(key: KeyPair, claim: str) -> None:
    overrides: dict[str, Any] = {claim: DROP}
    assert _reason(mint(key, **overrides), key) == "claims"


def test_future_iat_reason_claims(key: KeyPair) -> None:
    now = int(time.time())
    assert _reason(mint(key, iat=now + 120, exp=now + 900), key) == "claims"


@pytest.mark.parametrize("value", [False, DROP, "true", 1], ids=["false", "missing", "str", "1"])
def test_email_verified_false_or_missing(key: KeyPair, value: object) -> None:
    assert _reason(mint(key, email_verified=value), key) == "email_verified"


@pytest.mark.parametrize("token", ["abc", "a.b.c", ""])
def test_malformed_reason_malformed(key: KeyPair, token: str) -> None:
    assert _reason(token, key) == "malformed"


@pytest.mark.parametrize("leeway", [31, 3600])
def test_leeway_over_30_raises_value_error(key: KeyPair, leeway: int) -> None:
    with pytest.raises(ValueError):
        _verify(mint(key), key, leeway=leeway)


def test_error_repr_contains_no_token(key: KeyPair) -> None:
    token = mint(key, aud="stoktok")
    with pytest.raises(InvalidAccessTokenError) as exc_info:
        _verify(token, key)
    assert str(exc_info.value) == "audience"
    assert repr(exc_info.value) == "InvalidAccessTokenError('audience')"
    for part in token.split("."):
        assert part not in str(exc_info.value)
        assert part not in repr(exc_info.value)
        assert part not in repr(exc_info.value.args)
