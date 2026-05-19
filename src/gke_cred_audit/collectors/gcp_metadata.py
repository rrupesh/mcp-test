"""GCE/GKE metadata service collector.

Reads structured information from the link-local metadata endpoint at
http://169.254.169.254/. All token responses are redacted before they leave
this module. The legacy v1beta1 path is probed *without* the
`Metadata-Flavor: Google` header to detect environments where the GKE Metadata
Server (workload identity) is not enforced.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from ..config import Config
from ..models import (
    GcpAccessToken,
    GcpIdentityToken,
    GcpInstance,
    GcpMetadataInventory,
    JwtClaims,
    MetadataValue,
)
from ..redact import (
    decode_jwt_claims,
    is_sensitive_metadata_path,
    redact_metadata_value,
    redact_token,
)

_LOG = logging.getLogger("audit.gcp_metadata")
_FLAVOR = {"Metadata-Flavor": "Google"}


class GcpMetadataClient:
    def __init__(self, cfg: Config, client: httpx.AsyncClient | None = None) -> None:
        self.cfg = cfg
        self._client = client or httpx.AsyncClient(
            base_url=cfg.metadata_host,
            timeout=cfg.metadata_timeout_seconds,
            headers=_FLAVOR,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _get_text(self, path: str) -> str | None:
        try:
            r = await self._client.get(path)
            if r.status_code == 200:
                return r.text
            return None
        except httpx.HTTPError as exc:
            _LOG.debug("metadata fetch failed path=%s err=%s", path, exc)
            return None

    async def _get_json(self, path: str) -> Any | None:
        text = await self._get_text(path + ("?recursive=true&alt=json" if "?" not in path else ""))
        if text is None:
            return None
        try:
            import json

            return json.loads(text)
        except Exception:
            return text

    async def probe_legacy(self) -> bool:
        """Request /computeMetadata/v1beta1/project/project-id WITHOUT the
        Metadata-Flavor header. On a properly hardened GKE node (workload
        identity enforced via GKE Metadata Server) this returns 403/empty.
        """
        try:
            async with httpx.AsyncClient(
                base_url=self.cfg.metadata_host,
                timeout=self.cfg.metadata_timeout_seconds,
            ) as bare:
                r = await bare.get("/computeMetadata/v1beta1/project/project-id")
                return r.status_code == 200 and bool(r.text.strip())
        except httpx.HTTPError:
            return False

    async def list_service_accounts(self) -> list[str]:
        text = await self._get_text("/computeMetadata/v1/instance/service-accounts/")
        if not text:
            return []
        return [line.strip("/") for line in text.splitlines() if line.strip()]

    async def access_token(self, sa: str) -> GcpAccessToken | None:
        data = await self._get_json(f"/computeMetadata/v1/instance/service-accounts/{sa}/token")
        if not isinstance(data, dict) or "access_token" not in data:
            return None
        email = await self._get_text(f"/computeMetadata/v1/instance/service-accounts/{sa}/email")
        scopes_txt = await self._get_text(f"/computeMetadata/v1/instance/service-accounts/{sa}/scopes")
        scopes = [s.strip() for s in (scopes_txt or "").splitlines() if s.strip()]
        token = str(data.get("access_token", ""))
        return GcpAccessToken(
            service_account=sa,
            email=(email or "").strip() or None,
            scopes=scopes,
            expires_in=int(data.get("expires_in", 0)) or None,
            redaction=redact_token(token),
        )

    async def identity_token(self, sa: str, audience: str) -> GcpIdentityToken | None:
        text = await self._get_text(
            f"/computeMetadata/v1/instance/service-accounts/{sa}/identity?audience={audience}&format=full"
        )
        if not text:
            return None
        token = text.strip()
        try:
            claims = decode_jwt_claims(token)
        except ValueError:
            claims = JwtClaims()
        return GcpIdentityToken(
            service_account=sa,
            audience=audience,
            redaction=redact_token(token),
            claims=claims,
        )

    async def instance(self, legacy_reachable: bool) -> GcpInstance:
        async def t(p: str) -> str | None:
            v = await self._get_text(p)
            return v.strip() if v else None

        attrs = await self._get_text("/computeMetadata/v1/instance/attributes/")
        attribute_keys = sorted({line.strip().rstrip("/") for line in (attrs or "").splitlines() if line.strip()})

        return GcpInstance(
            project_id=await t("/computeMetadata/v1/project/project-id"),
            numeric_project_id=await t("/computeMetadata/v1/project/numeric-project-id"),
            instance_id=await t("/computeMetadata/v1/instance/id"),
            instance_name=await t("/computeMetadata/v1/instance/name"),
            zone=(await t("/computeMetadata/v1/instance/zone") or "").rsplit("/", 1)[-1] or None,
            machine_type=(await t("/computeMetadata/v1/instance/machine-type") or "").rsplit("/", 1)[-1] or None,
            hostname=await t("/computeMetadata/v1/instance/hostname"),
            attribute_keys=attribute_keys,
            legacy_metadata_reachable=legacy_reachable,
        )

    async def collect(self) -> GcpMetadataInventory:
        legacy = await self.probe_legacy()
        instance = await self.instance(legacy_reachable=legacy)
        sas = await self.list_service_accounts()
        access: list[GcpAccessToken] = []
        identity: list[GcpIdentityToken] = []
        for sa in sas:
            tok = await self.access_token(sa)
            if tok is not None:
                access.append(tok)
            if self.cfg.identity_audience:
                idt = await self.identity_token(sa, self.cfg.identity_audience)
                if idt is not None:
                    identity.append(idt)
        return GcpMetadataInventory(
            instance=instance,
            service_accounts=sas,
            access_tokens=access,
            identity_tokens=identity,
        )

    async def describe(self, path: str) -> MetadataValue:
        """Read an arbitrary metadata path and return a redacted result."""
        if not path.startswith("/"):
            path = "/" + path
        if not path.startswith("/computeMetadata/"):
            return MetadataValue(
                path=path,
                is_sensitive_path=False,
                redacted=False,
                value=None,
                note="path must begin with /computeMetadata/",
            )
        # Try JSON first for endpoints that support recursive=true; fall back
        # to text. Either way, redact_metadata_value sanitizes sensitive paths.
        raw_value: Any | None = None
        if "?" not in path:
            raw_value = await self._get_json(path)
        if raw_value is None:
            raw_value = await self._get_text(path)

        sensitive = is_sensitive_metadata_path(path)
        display, red, redacted = redact_metadata_value(path, raw_value)
        return MetadataValue(
            path=path,
            is_sensitive_path=sensitive,
            redacted=redacted,
            value=display,
            redaction=red,
            note=None if raw_value is not None else "no response",
        )
