"""Redaction utilities. Single source of truth for never leaking secret material.

All collectors call into this module before placing any captured token-like
material into a model that could be serialized to a client. The default
configuration NEVER returns raw values.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
from typing import Any

from .models import JwtClaims, TokenRedaction


_LOG = logging.getLogger("audit.redact")


def sha256_prefix(raw: str | bytes, n: int = 16) -> str:
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:n]


def looks_like_jwt(raw: str) -> bool:
    parts = raw.strip().split(".")
    return len(parts) == 3 and all(parts)


def redact_token(raw: str) -> TokenRedaction:
    kind = "jwt" if looks_like_jwt(raw) else "opaque"
    return TokenRedaction(kind=kind, length=len(raw), sha256_prefix=sha256_prefix(raw))


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def decode_jwt_claims(raw: str) -> JwtClaims:
    """Decode header and payload of a JWT. Signature is intentionally dropped.

    Raises ValueError on malformed input. The caller is responsible for
    treating the *raw* token as sensitive; this function only returns the
    non-secret claim metadata.
    """
    parts = raw.strip().split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as exc:  # pragma: no cover - defensive
        raise ValueError(f"failed to decode JWT segments: {exc}") from exc
    return JwtClaims(header=header, payload=payload)


SENSITIVE_PATH_HINTS = (
    "/token",
    "/identity",
    "service-accounts",
)


def is_sensitive_metadata_path(path: str) -> bool:
    p = path.lower()
    return any(h in p for h in SENSITIVE_PATH_HINTS)


def redact_metadata_value(path: str, value: Any) -> tuple[Any, TokenRedaction | None, bool]:
    """For describe_metadata: returns (display_value, redaction, redacted?).

    If the path is sensitive and value is a string-like token, the raw value is
    replaced with a redaction summary. JSON token responses (with `access_token`)
    have only the redaction surfaced.
    """
    if value is None:
        return None, None, False

    # GCE token JSON: {"access_token": "...", "expires_in": ..., "token_type": "..."}
    if isinstance(value, dict) and "access_token" in value:
        token = value.get("access_token") or ""
        red = redact_token(str(token))
        sanitized = {k: v for k, v in value.items() if k != "access_token"}
        sanitized["access_token"] = f"<redacted sha256:{red.sha256_prefix}>"
        return sanitized, red, True

    if isinstance(value, str) and is_sensitive_metadata_path(path):
        if looks_like_jwt(value) or len(value) >= 32:
            red = redact_token(value)
            return f"<redacted sha256:{red.sha256_prefix}>", red, True

    return value, None, False


class RawRevealGate:
    """Centralized gate for the off-by-default raw reveal path.

    The gate is *intentionally* small and explicit: any code path that calls
    `unwrap` must accept that doing so emits a WARNING and requires both the
    config flag and the request-level secret to match.
    """

    def __init__(self, enabled: bool, secret: str | None) -> None:
        self.enabled = bool(enabled)
        self._secret = secret

    def authorize(self, header_value: str | None) -> bool:
        if not self.enabled or not self._secret:
            return False
        return bool(header_value) and header_value == self._secret

    def unwrap(self, raw: str, *, header_value: str | None, source: str) -> str | None:
        if not self.authorize(header_value):
            return None
        _LOG.warning("audit.raw_reveal source=%s sha256=%s", source, sha256_prefix(raw))
        return raw
