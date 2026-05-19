"""Kubernetes API client + RBAC discovery (SelfSubjectRulesReview + SSAR matrix).

Talks to https://kubernetes.default.svc using the projected SA token. Validated
with the in-pod CA bundle. All requests are read-only and scoped to the
calling SA.
"""
from __future__ import annotations

import logging
import os
import ssl
from typing import Any

import httpx

from ..config import Config
from ..models import AccessReviewResult, RbacRule, RbacReport, RulesReviewResult

_LOG = logging.getLogger("audit.k8s_rbac")


# Curated risk matrix. Verbs/resources that, when allowed, materially increase
# blast radius. Kept short and meaningful so the result is human-readable.
CURATED_VERBS: tuple[str, ...] = (
    "get",
    "list",
    "watch",
    "create",
    "update",
    "patch",
    "delete",
    "impersonate",
    "escalate",
    "bind",
)

CURATED_RESOURCES: tuple[tuple[str, str | None, str], ...] = (
    # (resource, subresource, api_group)
    ("secrets", None, ""),
    ("pods", None, ""),
    ("pods", "exec", ""),
    ("pods", "attach", ""),
    ("pods", "portforward", ""),
    ("configmaps", None, ""),
    ("serviceaccounts", None, ""),
    ("serviceaccounts", "token", ""),
    ("roles", None, "rbac.authorization.k8s.io"),
    ("rolebindings", None, "rbac.authorization.k8s.io"),
    ("clusterroles", None, "rbac.authorization.k8s.io"),
    ("clusterrolebindings", None, "rbac.authorization.k8s.io"),
    ("nodes", None, ""),
    ("nodes", "proxy", ""),
    ("certificatesigningrequests", None, "certificates.k8s.io"),
    ("ephemeralcontainers", None, ""),
)


# Verb x resource pairs that we actually ask SSAR about. We avoid e.g. asking
# whether the SA can `escalate secrets` (nonsensical) by limiting verbs per
# resource group.
_VERB_FILTER = {
    "secrets": {"get", "list", "watch", "create", "update", "patch", "delete"},
    "pods": {"get", "list", "watch", "create", "update", "patch", "delete"},
    "pods/exec": {"create"},
    "pods/attach": {"create"},
    "pods/portforward": {"create"},
    "configmaps": {"get", "list", "watch", "create", "update", "patch", "delete"},
    "serviceaccounts": {"get", "list", "create", "patch", "update", "delete"},
    "serviceaccounts/token": {"create"},
    "roles": {"create", "update", "patch", "bind", "escalate"},
    "rolebindings": {"create", "update", "patch", "bind"},
    "clusterroles": {"create", "update", "patch", "bind", "escalate"},
    "clusterrolebindings": {"create", "update", "patch", "bind"},
    "nodes": {"get", "list", "patch", "update", "delete"},
    "nodes/proxy": {"get", "create"},
    "certificatesigningrequests": {"create", "approve"},
    "ephemeralcontainers": {"update", "patch"},
}


class K8sClient:
    def __init__(self, cfg: Config, client: httpx.AsyncClient | None = None) -> None:
        self.cfg = cfg
        self._token = self._read(cfg.k8s_token_path) or ""
        self._namespace = self._read(cfg.k8s_namespace_path) or "default"
        self._client = client or self._build_client()

    @staticmethod
    def _read(path: str) -> str | None:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            return None

    def _build_client(self) -> httpx.AsyncClient:
        verify: ssl.SSLContext | bool = True
        if os.path.isfile(self.cfg.k8s_ca_path):
            try:
                ctx = ssl.create_default_context(cafile=self.cfg.k8s_ca_path)
                verify = ctx
            except (ssl.SSLError, OSError) as exc:
                _LOG.warning("CA bundle %s unloadable, falling back to default: %s", self.cfg.k8s_ca_path, exc)
                verify = True
        headers = {"Accept": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return httpx.AsyncClient(
            base_url=self.cfg.k8s_api,
            verify=verify,
            headers=headers,
            timeout=5.0,
        )

    @property
    def namespace(self) -> str:
        return self._namespace

    async def aclose(self) -> None:
        await self._client.aclose()

    async def post(self, path: str, body: dict[str, Any]) -> dict[str, Any] | None:
        try:
            r = await self._client.post(path, json=body)
            if r.status_code >= 400:
                _LOG.debug("k8s post %s -> %s %s", path, r.status_code, r.text[:200])
                return None
            return r.json()
        except httpx.HTTPError as exc:
            _LOG.debug("k8s post %s err: %s", path, exc)
            return None

    async def get(self, path: str) -> dict[str, Any] | None:
        try:
            r = await self._client.get(path)
            if r.status_code >= 400:
                _LOG.debug("k8s get %s -> %s", path, r.status_code)
                return None
            return r.json()
        except httpx.HTTPError as exc:
            _LOG.debug("k8s get %s err: %s", path, exc)
            return None

    async def self_subject_rules_review(self, namespace: str | None = None) -> RulesReviewResult:
        ns = namespace or self._namespace
        body = {
            "kind": "SelfSubjectRulesReview",
            "apiVersion": "authorization.k8s.io/v1",
            "spec": {"namespace": ns},
        }
        data = await self.post("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", body)
        if not data:
            return RulesReviewResult(namespace=ns, incomplete=True)
        status = data.get("status") or {}
        rrules = [
            RbacRule(
                verbs=r.get("verbs", []) or [],
                api_groups=r.get("apiGroups", []) or [],
                resources=r.get("resources", []) or [],
                resource_names=r.get("resourceNames", []) or [],
            )
            for r in status.get("resourceRules", []) or []
        ]
        nrules = [
            RbacRule(
                verbs=r.get("verbs", []) or [],
                non_resource_urls=r.get("nonResourceURLs", []) or [],
            )
            for r in status.get("nonResourceRules", []) or []
        ]
        return RulesReviewResult(
            namespace=ns,
            incomplete=bool(status.get("incomplete", False)),
            resource_rules=rrules,
            non_resource_rules=nrules,
        )

    async def self_subject_access_review(
        self, *, verb: str, resource: str, subresource: str | None, group: str, namespace: str | None
    ) -> AccessReviewResult:
        attrs: dict[str, Any] = {"verb": verb, "resource": resource, "group": group}
        if subresource:
            attrs["subresource"] = subresource
        if namespace:
            attrs["namespace"] = namespace
        body = {
            "kind": "SelfSubjectAccessReview",
            "apiVersion": "authorization.k8s.io/v1",
            "spec": {"resourceAttributes": attrs},
        }
        data = await self.post("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", body)
        status = (data or {}).get("status") or {}
        return AccessReviewResult(
            verb=verb,
            resource=resource,
            subresource=subresource,
            namespace=namespace,
            allowed=bool(status.get("allowed")),
            reason=(status.get("reason") or status.get("evaluationError")) or None,
        )


async def collect_rbac(cfg: Config, client: K8sClient | None = None) -> RbacReport:
    own = client or K8sClient(cfg)
    try:
        rules = await own.self_subject_rules_review()
        curated: list[AccessReviewResult] = []
        for resource, subresource, group in CURATED_RESOURCES:
            full = resource + (f"/{subresource}" if subresource else "")
            verbs = _VERB_FILTER.get(full, set(CURATED_VERBS))
            for verb in verbs:
                # Cluster-scoped resources: don't pass a namespace.
                ns = None if resource in {"nodes", "clusterroles", "clusterrolebindings", "certificatesigningrequests"} else own.namespace
                curated.append(
                    await own.self_subject_access_review(
                        verb=verb,
                        resource=resource,
                        subresource=subresource,
                        group=group,
                        namespace=ns,
                    )
                )
        return RbacReport(rules=rules, curated=curated)
    finally:
        if client is None:
            await own.aclose()
