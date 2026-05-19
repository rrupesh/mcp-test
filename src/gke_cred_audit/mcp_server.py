"""MCP server over Streamable HTTP, mounted at /mcp.

Tools/resources are read-only and consume the same redacted models as REST.
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import __version__
from .audit import run_audit
from .collectors.gcp_metadata import GcpMetadataClient
from .collectors.k8s_namespace import (
    collect_namespace,
    list_namespace_configmaps,
    list_namespace_pods,
    list_namespace_secrets,
)
from .collectors.k8s_rbac import K8sClient
from .collectors.k8s_sa_tokens import collect_k8s_credentials
from .config import Config
from .models import (
    AccessReviewResult,
    ConfigMapMeta,
    CredentialInventory,
    FindingList,
    MetadataValue,
    NamespacePosture,
    PodPosture,
    Report,
    RulesReviewResult,
    SecretMeta,
    ServerInfo,
    ServerInfoResource,
    ServerInfoTool,
    Severity,
)


def build_mcp(cfg: Config) -> FastMCP:
    mcp = FastMCP(
        "gke-cred-audit",
        instructions=(
            "Read-only inventory of credentials and namespace posture. Deployed via Natoma "
            f"(Natoma is the auth boundary; this server has no native auth). "
            f"raw_reveal_enabled={cfg.raw_reveal} secret_listing_enabled={cfg.enable_secret_listing}. "
            "Tokens, JWT signatures, and Secret values are never returned."
        ),
        json_response=False,
    )
    sec = mcp.settings.transport_security
    sec.allowed_hosts = list({*sec.allowed_hosts, "127.0.0.1", "localhost", "[::1]", "*"})
    sec.allowed_origins = list({*sec.allowed_origins, "http://127.0.0.1", "http://localhost", "http://[::1]"})

    @mcp.tool(description="Full audit report (credentials, RBAC, namespace, findings).")
    async def get_report() -> Report:
        return await run_audit(cfg)

    @mcp.tool(description="Credentials this pod has access to (GCE MDS + projected SA + mounted files). Redacted.")
    async def list_credentials() -> CredentialInventory:
        gcp_client = GcpMetadataClient(cfg)
        try:
            gcp = await gcp_client.collect()
        finally:
            await gcp_client.aclose()
        return CredentialInventory(gcp=gcp, k8s=collect_k8s_credentials(cfg))

    @mcp.tool(description="Severity-tagged findings derived from the inventory.")
    async def get_findings(severity: Severity | None = None) -> FindingList:
        report = await run_audit(cfg)
        if severity is None:
            return report.findings
        return FindingList(items=[f for f in report.findings.items if f.severity == severity])

    @mcp.tool(description="Read a specific GCE metadata path (auto-redacts secret-bearing responses).")
    async def describe_metadata(path: str) -> MetadataValue:
        client = GcpMetadataClient(cfg)
        try:
            return await client.describe(path)
        finally:
            await client.aclose()

    @mcp.tool(description="SelfSubjectAccessReview: can this SA perform <verb> on <resource>?")
    async def check_permission(
        verb: str, resource: str, subresource: str | None = None, namespace: str | None = None, group: str = ""
    ) -> AccessReviewResult:
        client = K8sClient(cfg)
        try:
            return await client.self_subject_access_review(
                verb=verb,
                resource=resource,
                subresource=subresource,
                group=group,
                namespace=namespace if namespace is not None else client.namespace,
            )
        finally:
            await client.aclose()

    @mcp.tool(description="SelfSubjectRulesReview for the pod's namespace.")
    async def list_sa_rules() -> RulesReviewResult:
        client = K8sClient(cfg)
        try:
            return await client.self_subject_rules_review()
        finally:
            await client.aclose()

    @mcp.tool(description="Namespace posture: pods, configmaps, secrets-meta (when enabled).")
    async def get_namespace() -> NamespacePosture:
        return await collect_namespace(cfg)

    @mcp.tool(description="Pods in this pod's namespace with derived security posture.")
    async def list_namespace_pods_tool() -> list[PodPosture]:
        return await list_namespace_pods(cfg)

    @mcp.tool(description="ConfigMaps in this pod's namespace (names + key list, not values).")
    async def list_namespace_configmaps_tool() -> list[ConfigMapMeta]:
        return await list_namespace_configmaps(cfg)

    @mcp.tool(description="Secrets in this pod's namespace as METADATA ONLY (names, types, key sizes, sha256 prefixes). Values are never returned.")
    async def list_namespace_secrets_tool() -> list[SecretMeta] | None:
        return await list_namespace_secrets(cfg)

    @mcp.tool(description="Posture for a specific pod by name in this pod's namespace.")
    async def describe_pod(name: str) -> PodPosture | None:
        for p in await list_namespace_pods(cfg):
            if p.name == name:
                return p
        return None

    @mcp.tool(description="Static server info (name, version, deployment, capabilities).")
    async def server_info() -> ServerInfo:
        return _server_info(cfg, mcp)

    @mcp.resource("audit://report", description="Full audit report as JSON.")
    async def res_report() -> str:
        return (await run_audit(cfg)).model_dump_json(indent=2)

    @mcp.resource("audit://findings", description="Findings list as JSON.")
    async def res_findings() -> str:
        return (await run_audit(cfg)).findings.model_dump_json(indent=2)

    @mcp.resource("audit://namespace/pods", description="Pods in this pod's namespace.")
    async def res_ns_pods() -> str:
        return NamespacePosture(
            namespace=K8sClient(cfg).namespace,
            pods=await list_namespace_pods(cfg),
        ).model_dump_json(indent=2)

    @mcp.resource("audit://namespace/configmaps", description="ConfigMap metadata in this namespace.")
    async def res_ns_cms() -> str:
        cms = await list_namespace_configmaps(cfg)
        return NamespacePosture(namespace=K8sClient(cfg).namespace, configmaps=cms).model_dump_json(indent=2)

    @mcp.resource("audit://namespace/secrets", description="Secret metadata in this namespace (values never returned).")
    async def res_ns_secrets() -> str:
        secrets = await list_namespace_secrets(cfg)
        return NamespacePosture(
            namespace=K8sClient(cfg).namespace,
            secrets=secrets,
            secret_listing_enabled=cfg.enable_secret_listing,
        ).model_dump_json(indent=2)

    @mcp.resource("audit://server-info", description="Static server info and capability summary.")
    async def res_server_info() -> str:
        return _server_info(cfg, mcp).model_dump_json(indent=2)

    @mcp.prompt(description="Suggest remediation context for a given finding id.")
    async def remediate(finding_id: str) -> str:
        report = await run_audit(cfg)
        match = next((f for f in report.findings.items if f.id == finding_id), None)
        if not match:
            return f"No active finding with id {finding_id!r}."
        return (
            f"Finding {match.id} ({match.severity.value})\n"
            f"Title: {match.title}\n\n"
            f"Detail: {match.detail}\n\n"
            f"Suggested remediation: {match.remediation}\n\n"
            f"Evidence: {match.evidence}"
        )

    return mcp


def _server_info(cfg: Config, mcp: FastMCP) -> ServerInfo:
    tools = [ServerInfoTool(name=t.name, description=t.description) for t in mcp._tool_manager.list_tools()]
    resources = [
        ServerInfoResource(uri=str(r.uri), description=r.description)
        for r in mcp._resource_manager.list_resources()
    ]
    return ServerInfo(
        version=__version__,
        deployment="natoma",
        auth="none (gateway-managed)",
        raw_reveal_enabled=cfg.raw_reveal,
        secret_listing_enabled=cfg.enable_secret_listing,
        tools=tools,
        resources=resources,
    )
