"""Namespace-scoped collector.

Reads pods, configmaps, and (opt-in) secret *metadata only* from the API
server using the pod's ServiceAccount. Secret values are NEVER returned: only
each key's name, size in bytes, and sha256 prefix. The collector intentionally
filters `data` and `stringData` immediately after deserialization.
"""
from __future__ import annotations

import base64
import logging
from typing import Any

from ..config import Config
from ..models import (
    ConfigMapMeta,
    NamespacePosture,
    PodPosture,
    SecretKeyMeta,
    SecretMeta,
)
from ..redact import sha256_prefix
from .k8s_rbac import K8sClient

_LOG = logging.getLogger("audit.k8s_namespace")


def _derive_risk_tags(p: PodPosture) -> list[str]:
    tags: list[str] = []
    if p.privileged:
        tags.append("privileged")
    if p.host_pid:
        tags.append("hostPID")
    if p.host_network:
        tags.append("hostNetwork")
    if p.host_ipc:
        tags.append("hostIPC")
    if p.allow_privilege_escalation:
        tags.append("allowPrivilegeEscalation")
    if p.automount_service_account_token is None or p.automount_service_account_token:
        tags.append("saTokenAutomounted")
    if len(p.secret_volumes) > 1:
        tags.append("multipleSecretVolumes")
    return tags


def _to_pod_posture(item: dict[str, Any]) -> PodPosture:
    md = item.get("metadata") or {}
    spec = item.get("spec") or {}
    pod_sc = spec.get("securityContext") or {}
    privileged = False
    aple: bool | None = None
    for c in (spec.get("containers") or []) + (spec.get("initContainers") or []):
        sc = c.get("securityContext") or {}
        if sc.get("privileged"):
            privileged = True
        if sc.get("allowPrivilegeEscalation") is True:
            aple = True
        elif aple is None and sc.get("allowPrivilegeEscalation") is False:
            aple = False
    secret_vols: list[str] = []
    cm_vols: list[str] = []
    for v in spec.get("volumes") or []:
        if "secret" in v:
            n = v.get("secret", {}).get("secretName") or v.get("name")
            if n:
                secret_vols.append(n)
        if "configMap" in v:
            n = v.get("configMap", {}).get("name") or v.get("name")
            if n:
                cm_vols.append(n)

    posture = PodPosture(
        namespace=md.get("namespace") or "",
        name=md.get("name") or "",
        service_account=spec.get("serviceAccountName") or spec.get("serviceAccount"),
        automount_service_account_token=spec.get("automountServiceAccountToken"),
        secret_volumes=sorted(set(secret_vols)),
        configmap_volumes=sorted(set(cm_vols)),
        privileged=privileged or bool(pod_sc.get("privileged", False)),
        host_pid=bool(spec.get("hostPID", False)),
        host_network=bool(spec.get("hostNetwork", False)),
        host_ipc=bool(spec.get("hostIPC", False)),
        allow_privilege_escalation=aple,
    )
    posture.risk_tags = _derive_risk_tags(posture)
    return posture


def _decode_secret_value(value: Any) -> bytes:
    """Decode a Secret data map entry. The decoded bytes never leave the local
    scope of this function; only the size and sha256 prefix are surfaced."""
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    s = str(value)
    try:
        return base64.b64decode(s, validate=False)
    except Exception:
        return s.encode("utf-8", errors="replace")


def _to_secret_meta(item: dict[str, Any]) -> SecretMeta:
    md = item.get("metadata") or {}
    name = md.get("name") or ""
    typ = item.get("type")
    keys: list[SecretKeyMeta] = []
    data = item.get("data") or {}
    string_data = item.get("stringData") or {}
    seen: set[str] = set()
    for k, v in data.items():
        decoded = _decode_secret_value(v)
        keys.append(SecretKeyMeta(name=k, size=len(decoded), sha256_prefix=sha256_prefix(decoded)))
        seen.add(k)
    for k, v in string_data.items():
        if k in seen:
            continue
        b = (v or "").encode("utf-8") if isinstance(v, str) else _decode_secret_value(v)
        keys.append(SecretKeyMeta(name=k, size=len(b), sha256_prefix=sha256_prefix(b)))
    keys.sort(key=lambda k: k.name)
    return SecretMeta(name=name, type=typ, keys=keys)


def _to_configmap_meta(item: dict[str, Any]) -> ConfigMapMeta:
    md = item.get("metadata") or {}
    data = item.get("data") or {}
    binary = item.get("binaryData") or {}
    keys = sorted(set(list(data.keys()) + list(binary.keys())))
    return ConfigMapMeta(name=md.get("name") or "", keys=keys)


async def list_namespace_pods(cfg: Config, client: K8sClient | None = None) -> list[PodPosture]:
    own = client or K8sClient(cfg)
    try:
        ns = own.namespace
        data = await own.get(f"/api/v1/namespaces/{ns}/pods")
        items = (data or {}).get("items") or []
        return [_to_pod_posture(it) for it in items]
    finally:
        if client is None:
            await own.aclose()


async def list_namespace_configmaps(cfg: Config, client: K8sClient | None = None) -> list[ConfigMapMeta]:
    own = client or K8sClient(cfg)
    try:
        ns = own.namespace
        data = await own.get(f"/api/v1/namespaces/{ns}/configmaps")
        items = (data or {}).get("items") or []
        return [_to_configmap_meta(it) for it in items]
    finally:
        if client is None:
            await own.aclose()


async def list_namespace_secrets(cfg: Config, client: K8sClient | None = None) -> list[SecretMeta] | None:
    """Returns secret metadata (names/keys/sizes/sha256-prefixes). Values are
    never returned. Returns None when secret listing is not enabled.
    """
    if not cfg.enable_secret_listing:
        return None
    own = client or K8sClient(cfg)
    try:
        ns = own.namespace
        data = await own.get(f"/api/v1/namespaces/{ns}/secrets")
        items = (data or {}).get("items") or []
        return [_to_secret_meta(it) for it in items]
    finally:
        if client is None:
            await own.aclose()


async def collect_namespace(cfg: Config, client: K8sClient | None = None) -> NamespacePosture:
    own = client or K8sClient(cfg)
    try:
        ns = own.namespace
        try:
            pods = await list_namespace_pods(cfg, client=own)
        except Exception:
            pods = []
        try:
            cms = await list_namespace_configmaps(cfg, client=own)
        except Exception:
            cms = []
        try:
            secrets = await list_namespace_secrets(cfg, client=own)
        except Exception:
            secrets = None
        return NamespacePosture(
            namespace=ns,
            pods=pods,
            configmaps=cms,
            secrets=secrets,
            secret_listing_enabled=cfg.enable_secret_listing,
        )
    finally:
        if client is None:
            await own.aclose()
