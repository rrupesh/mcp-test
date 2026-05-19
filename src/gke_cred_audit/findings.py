"""Findings engine: derives severity-tagged issues from collected inventory."""
from __future__ import annotations

from .models import (
    AccessReviewResult,
    CredentialInventory,
    Finding,
    FindingList,
    NamespacePosture,
    RbacReport,
    Severity,
)


def _was_allowed(curated: list[AccessReviewResult], *, verb: str, resource: str, subresource: str | None = None) -> bool:
    for r in curated:
        if r.allowed and r.verb == verb and r.resource == resource and (r.subresource or None) == subresource:
            return True
    return False


def evaluate(
    creds: CredentialInventory,
    rbac: RbacReport,
    namespace: NamespacePosture | None = None,
) -> FindingList:
    out: list[Finding] = []

    # GCP-SA-CLOUD-PLATFORM
    for tok in creds.gcp.access_tokens:
        if any(s.endswith("/cloud-platform") for s in tok.scopes):
            out.append(
                Finding(
                    id="GCP-SA-CLOUD-PLATFORM",
                    severity=Severity.HIGH,
                    title="GCP service account has cloud-platform scope",
                    detail=(
                        "The instance/workload service account "
                        f"{tok.email or tok.service_account!r} is exposing a token with the "
                        "broad cloud-platform OAuth scope, which grants access to the full set of "
                        "Google Cloud APIs the SA has IAM permissions for."
                    ),
                    remediation=(
                        "Bind a dedicated GCP service account via Workload Identity with the minimum required "
                        "scopes/roles. Avoid running with the default Compute Engine SA."
                    ),
                    evidence={"service_account": tok.email or tok.service_account, "scopes": tok.scopes},
                )
            )

    # GKE-LEGACY-METADATA
    if creds.gcp.instance.legacy_metadata_reachable:
        out.append(
            Finding(
                id="GKE-LEGACY-METADATA",
                severity=Severity.HIGH,
                title="Legacy GCE metadata endpoint reachable from pod",
                detail=(
                    "The /computeMetadata/v1beta1/* path responded without the Metadata-Flavor header, "
                    "indicating the GKE Metadata Server is not enforcing workload identity for this pod."
                ),
                remediation=(
                    "Enable Workload Identity on the cluster and the node pool "
                    "(--workload-pool / --workload-metadata=GKE_METADATA), and add a NetworkPolicy that "
                    "blocks egress to 169.254.169.254 from workload pods."
                ),
                evidence={"path": "/computeMetadata/v1beta1/project/project-id"},
            )
        )

    # K8S-* RBAC findings (self-RBAC)
    risk_rules = [
        ("K8S-SECRETS-READ", Severity.HIGH, "get", "secrets", None,
         "ServiceAccount can read Kubernetes Secrets",
         "Replace with least-privilege Role(s); store sensitive data in External Secrets / Secret Manager."),
        ("K8S-SECRETS-LIST", Severity.HIGH, "list", "secrets", None,
         "ServiceAccount can list Kubernetes Secrets",
         "Same as get; granting list expands blast radius further."),
        ("K8S-PODS-EXEC", Severity.HIGH, "create", "pods", "exec",
         "ServiceAccount can exec into pods",
         "Remove pods/exec verb; use ephemeral debug containers gated behind privileged review."),
        ("K8S-PODS-ATTACH", Severity.HIGH, "create", "pods", "attach",
         "ServiceAccount can attach to pods",
         "Remove pods/attach."),
        ("K8S-PODS-PORTFORWARD", Severity.HIGH, "create", "pods", "portforward",
         "ServiceAccount can port-forward pods",
         "Remove pods/portforward."),
        ("K8S-IMPERSONATE", Severity.CRITICAL, "impersonate", "serviceaccounts", None,
         "ServiceAccount can impersonate identities",
         "Drop impersonate verb; replace with explicit RoleBinding."),
        ("K8S-TOKEN-CREATE", Severity.CRITICAL, "create", "serviceaccounts", "token",
         "ServiceAccount can mint tokens for other SAs",
         "Remove serviceaccounts/token:create; use bound projected tokens instead."),
        ("K8S-RBAC-BIND", Severity.CRITICAL, "bind", "rolebindings", None,
         "ServiceAccount can create RoleBindings",
         "Remove bind verb on RBAC resources to prevent privilege escalation."),
        ("K8S-RBAC-ESCALATE", Severity.CRITICAL, "escalate", "roles", None,
         "ServiceAccount can escalate Role permissions",
         "Remove escalate verb on rbac.authorization.k8s.io/roles."),
    ]
    for fid, sev, verb, resource, subresource, title, remediation in risk_rules:
        if _was_allowed(rbac.curated, verb=verb, resource=resource, subresource=subresource):
            out.append(
                Finding(
                    id=fid,
                    severity=sev,
                    title=title,
                    detail=f"SelfSubjectAccessReview allowed verb={verb} resource={resource}"
                    + (f"/{subresource}" if subresource else ""),
                    remediation=remediation,
                    evidence={"verb": verb, "resource": resource, "subresource": subresource},
                )
            )

    # SA-TOKEN-AUTOMOUNTED
    if creds.k8s.projected_token is not None:
        out.append(
            Finding(
                id="SA-TOKEN-AUTOMOUNTED",
                severity=Severity.MEDIUM,
                title="Projected ServiceAccount token mounted in pod",
                detail=(
                    "A projected token is present at /var/run/secrets/kubernetes.io/serviceaccount/token. "
                    "If the workload does not call the Kubernetes API, this is unnecessary attack surface."
                ),
                remediation=(
                    "Set automountServiceAccountToken: false on the pod or ServiceAccount. If the workload "
                    "needs Kubernetes API access, scope the audience and short-circuit the token via projected "
                    "volume with audience+expiration."
                ),
                evidence={"sha256_prefix": creds.k8s.projected_token.redaction.sha256_prefix},
            )
        )

    # SECRETS-MOUNTED (extra files beyond SA token bundle)
    extra = [
        f for f in creds.k8s.mounted_secret_files
        if not f.path.startswith("/var/run/secrets/kubernetes.io/serviceaccount/")
    ]
    if extra:
        out.append(
            Finding(
                id="SECRETS-MOUNTED",
                severity=Severity.INFO,
                title="Additional secret files mounted in the pod",
                detail=f"{len(extra)} non-SA secret file(s) mounted; review whether each is required.",
                remediation="Audit volume mounts; prefer environment-injected references via External Secrets "
                "/ CSI Secret Store with shortest-possible TTLs.",
                evidence={"files": [f.path for f in extra[:25]]},
            )
        )

    # Namespace-scoped findings.
    if namespace is not None:
        # NS-SECRETS-LIST-GRANTED -- SA has secrets:list AND/OR enable_secret_listing is on.
        sa_can_list_secrets = _was_allowed(rbac.curated, verb="list", resource="secrets")
        if sa_can_list_secrets and namespace.secret_listing_enabled:
            out.append(
                Finding(
                    id="NS-SECRETS-LIST-GRANTED",
                    severity=Severity.HIGH,
                    title="Namespace secret enumeration is enabled and permitted",
                    detail=(
                        "This SA can list Secrets in the namespace AND the audit server is configured to "
                        "enumerate them (AUDIT_ENABLE_SECRET_LISTING=true). Even though Secret values are "
                        "never returned by this server, granting secrets:list to the audit SA is a high-trust "
                        "decision: any compromise of the audit pod would expose the values to whatever "
                        "process replaces this code."
                    ),
                    remediation=(
                        "Disable AUDIT_ENABLE_SECRET_LISTING unless secret enumeration is explicitly required. "
                        "If required, isolate the audit Deployment in its own namespace with no other workloads "
                        "and tighten the Role to specific secretNames using resourceNames."
                    ),
                    evidence={"namespace": namespace.namespace, "secret_count": len(namespace.secrets or [])},
                )
            )

        if namespace.pods:
            priv = [p for p in namespace.pods if p.privileged]
            if priv:
                out.append(
                    Finding(
                        id="NS-PRIVILEGED-PODS",
                        severity=Severity.HIGH,
                        title="Privileged pods present in the namespace",
                        detail=f"{len(priv)} pod(s) running with privileged=true.",
                        remediation="Replace privileged containers with capability-scoped specs; enforce "
                        "PodSecurity admission `restricted` profile on the namespace.",
                        evidence={"pods": [f"{p.namespace}/{p.name}" for p in priv][:25]},
                    )
                )
            host_ns = [p for p in namespace.pods if p.host_pid or p.host_network or p.host_ipc]
            if host_ns:
                out.append(
                    Finding(
                        id="NS-HOST-NAMESPACES",
                        severity=Severity.MEDIUM,
                        title="Pods using host namespaces in this namespace",
                        detail=f"{len(host_ns)} pod(s) with hostPID/hostNetwork/hostIPC.",
                        remediation="Remove host namespace usage; gate exceptions through PSA `privileged` "
                        "namespaces only.",
                        evidence={"pods": [f"{p.namespace}/{p.name}" for p in host_ns][:25]},
                    )
                )
            sa_counts: dict[str, list[str]] = {}
            for p in namespace.pods:
                if p.service_account:
                    sa_counts.setdefault(p.service_account, []).append(p.name)
            shared = {k: v for k, v in sa_counts.items() if len(v) > 1}
            if shared:
                out.append(
                    Finding(
                        id="NS-SHARED-SA",
                        severity=Severity.LOW,
                        title="Multiple pods share the same ServiceAccount in this namespace",
                        detail="Shared SAs increase blast radius if any one workload is compromised.",
                        remediation="Provision per-workload ServiceAccounts with narrow RoleBindings.",
                        evidence={k: v for k, v in list(shared.items())[:10]},
                    )
                )

    return FindingList(items=out)
