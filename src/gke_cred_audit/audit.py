"""Top-level orchestration: invoke collectors, derive findings, build a Report."""
from __future__ import annotations

from .collectors.gcp_metadata import GcpMetadataClient
from .collectors.k8s_namespace import collect_namespace
from .collectors.k8s_rbac import K8sClient, collect_rbac
from .collectors.k8s_sa_tokens import collect_k8s_credentials
from .config import Config
from .findings import evaluate
from .models import (
    CredentialInventory,
    GcpInstance,
    GcpMetadataInventory,
    NamespacePosture,
    RbacReport,
    Report,
    RulesReviewResult,
)


async def run_audit(cfg: Config) -> Report:
    # GCP metadata
    gcp_client = GcpMetadataClient(cfg)
    try:
        try:
            gcp = await gcp_client.collect()
        except Exception:
            gcp = GcpMetadataInventory(instance=GcpInstance())
    finally:
        await gcp_client.aclose()

    # Local pod creds
    k8s_creds = collect_k8s_credentials(cfg)
    creds = CredentialInventory(gcp=gcp, k8s=k8s_creds)

    # RBAC + namespace posture share a single client.
    k8s_client = K8sClient(cfg)
    try:
        try:
            rbac = await collect_rbac(cfg, client=k8s_client)
        except Exception:
            rbac = RbacReport(rules=RulesReviewResult(namespace=k8s_client.namespace, incomplete=True))

        try:
            namespace = await collect_namespace(cfg, client=k8s_client)
        except Exception:
            namespace = NamespacePosture(
                namespace=k8s_client.namespace,
                secret_listing_enabled=cfg.enable_secret_listing,
            )
    finally:
        await k8s_client.aclose()

    findings = evaluate(creds, rbac, namespace)
    return Report(
        raw_reveal_enabled=cfg.raw_reveal,
        deployment="natoma",
        auth="none (gateway-managed)",
        secret_listing_enabled=cfg.enable_secret_listing,
        credentials=creds,
        rbac=rbac,
        findings=findings,
        namespace=namespace,
    )
