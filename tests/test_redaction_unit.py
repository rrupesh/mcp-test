"""Unit tests for the redaction module."""
from __future__ import annotations

import pytest

from gke_cred_audit.redact import (
    decode_jwt_claims,
    looks_like_jwt,
    redact_metadata_value,
    redact_token,
    sha256_prefix,
)


JWT = (
    "eyJhbGciOiJIUzI1NiJ9."
    "eyJzdWIiOiJhYWEiLCJpc3MiOiJodHRwczovL2lzc3Vlci8iLCJhdWQiOiJodHRwczovL2F1ZC8ifQ."
    "X8a8XL_Z2Y_signature"
)


def test_redact_token_jwt():
    r = redact_token(JWT)
    assert r.kind == "jwt"
    assert r.length == len(JWT)
    assert len(r.sha256_prefix) == 16


def test_redact_token_opaque():
    r = redact_token("ya29.opaqueblob")
    assert r.kind == "opaque"


def test_decode_jwt_claims_drops_signature():
    c = decode_jwt_claims(JWT)
    assert c.payload["sub"] == "aaa"
    # The returned object never contains the signature segment.
    s = c.model_dump_json()
    assert JWT.split(".")[2] not in s


def test_redact_metadata_value_token_response_redacts():
    sanitized, red, redacted = redact_metadata_value(
        "/computeMetadata/v1/instance/service-accounts/default/token",
        {"access_token": "ya29.SECRET", "expires_in": 100, "token_type": "Bearer"},
    )
    assert redacted is True
    assert sanitized["access_token"].startswith("<redacted")
    assert sanitized["expires_in"] == 100
    assert red is not None


def test_looks_like_jwt():
    assert looks_like_jwt(JWT)
    assert not looks_like_jwt("plain")


def test_sha256_prefix_stable():
    assert sha256_prefix("abc") == sha256_prefix("abc")
