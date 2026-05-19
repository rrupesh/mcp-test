"""Shared pydantic models for REST + MCP surfaces.

Every model in this file is designed to be safely serializable to a public JSON
response. None of these models carry raw bearer tokens, JWT signatures, or PEM
key material. Redacted equivalents (sha256 prefix, claims, scopes) are used.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Problem(BaseModel):
    """RFC 7807 problem details."""

    type: str = Field("about:blank", examples=["about:blank"])
    title: str = Field(..., examples=["Not Found"])
    status: int = Field(..., examples=[404])
    detail: str | None = Field(None, examples=["resource not found"])
    instance: str | None = Field(None, examples=["/findings/missing"])


class TokenRedaction(BaseModel):
    kind: Literal["jwt", "opaque"] = Field(..., examples=["jwt"])
    length: int = Field(..., examples=[1024])
    sha256_prefix: str = Field(..., description="First 16 hex chars of SHA-256.", examples=["ab12cd34ef567890"])


class JwtClaims(BaseModel):
    header: dict[str, Any] = Field(default_factory=dict)
    payload: dict[str, Any] = Field(default_factory=dict)


class GcpAccessToken(BaseModel):
    service_account: str = Field(..., examples=["default"])
    email: str | None = Field(None, examples=["sa@project.iam.gserviceaccount.com"])
    scopes: list[str] = Field(default_factory=list)
    expires_in: int | None = Field(None, examples=[3599])
    redaction: TokenRedaction


class GcpIdentityToken(BaseModel):
    service_account: str
    audience: str
    redaction: TokenRedaction
    claims: JwtClaims


class GcpInstance(BaseModel):
    project_id: str | None = None
    numeric_project_id: str | None = None
    instance_id: str | None = None
    instance_name: str | None = None
    zone: str | None = None
    machine_type: str | None = None
    hostname: str | None = None
    attribute_keys: list[str] = Field(default_factory=list)
    legacy_metadata_reachable: bool = Field(
        False,
        description="True when /computeMetadata/v1beta1/* responds without Metadata-Flavor (workload identity not enforced).",
    )


class GcpMetadataInventory(BaseModel):
    instance: GcpInstance
    service_accounts: list[str] = Field(default_factory=list)
    access_tokens: list[GcpAccessToken] = Field(default_factory=list)
    identity_tokens: list[GcpIdentityToken] = Field(default_factory=list)


class MetadataValue(BaseModel):
    """Result of a structured `describe_metadata` call. Auto-redacted."""

    path: str
    is_sensitive_path: bool = False
    redacted: bool = False
    value: Any | None = None
    redaction: TokenRedaction | None = None
    note: str | None = None


class MountedSecretFile(BaseModel):
    path: str
    size: int
    sha256_prefix: str
    kind: Literal["jwt", "pem-private-key", "kubeconfig", "opaque"] = "opaque"


class ProjectedSaToken(BaseModel):
    namespace: str | None = None
    redaction: TokenRedaction
    claims: JwtClaims


class K8sCredentialInventory(BaseModel):
    projected_token: ProjectedSaToken | None = None
    ca_present: bool = False
    mounted_secret_files: list[MountedSecretFile] = Field(default_factory=list)


class CredentialInventory(BaseModel):
    gcp: GcpMetadataInventory
    k8s: K8sCredentialInventory


class RbacRule(BaseModel):
    verbs: list[str] = Field(default_factory=list)
    api_groups: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    resource_names: list[str] = Field(default_factory=list)
    non_resource_urls: list[str] = Field(default_factory=list)


class RulesReviewResult(BaseModel):
    namespace: str
    incomplete: bool = False
    resource_rules: list[RbacRule] = Field(default_factory=list)
    non_resource_rules: list[RbacRule] = Field(default_factory=list)


class AccessReviewResult(BaseModel):
    verb: str
    resource: str
    subresource: str | None = None
    namespace: str | None = None
    allowed: bool
    reason: str | None = None


class RbacReport(BaseModel):
    rules: RulesReviewResult
    curated: list[AccessReviewResult] = Field(default_factory=list)


class Finding(BaseModel):
    id: str = Field(..., examples=["K8S-SECRETS-READ"])
    severity: Severity
    title: str
    detail: str
    remediation: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class FindingList(BaseModel):
    items: list[Finding] = Field(default_factory=list)


class PodPosture(BaseModel):
    namespace: str
    name: str
    service_account: str | None = None
    automount_service_account_token: bool | None = None
    secret_volumes: list[str] = Field(default_factory=list)
    configmap_volumes: list[str] = Field(default_factory=list)
    privileged: bool = False
    host_pid: bool = False
    host_network: bool = False
    host_ipc: bool = False
    allow_privilege_escalation: bool | None = None
    risk_tags: list[str] = Field(default_factory=list)


class ConfigMapMeta(BaseModel):
    name: str
    keys: list[str] = Field(default_factory=list)


class SecretKeyMeta(BaseModel):
    name: str = Field(..., description="Key name inside the Secret data map.")
    size: int = Field(..., description="Length of the decoded value in bytes.")
    sha256_prefix: str = Field(..., description="First 16 hex chars of SHA-256 of the decoded value.")


class SecretMeta(BaseModel):
    name: str
    type: str | None = None
    keys: list[SecretKeyMeta] = Field(default_factory=list)


class NamespacePosture(BaseModel):
    namespace: str
    pods: list[PodPosture] = Field(default_factory=list)
    configmaps: list[ConfigMapMeta] = Field(default_factory=list)
    secrets: list[SecretMeta] | None = Field(
        default=None,
        description="Populated only when AUDIT_ENABLE_SECRET_LISTING is true. Values are never returned.",
    )
    secret_listing_enabled: bool = False


class Report(BaseModel):
    raw_reveal_enabled: bool = False
    deployment: str = "natoma"
    auth: str = "none (gateway-managed)"
    secret_listing_enabled: bool = False
    credentials: CredentialInventory
    rbac: RbacReport
    findings: FindingList
    namespace: NamespacePosture | None = None


class ServerInfoTool(BaseModel):
    name: str
    description: str | None = None


class ServerInfoResource(BaseModel):
    uri: str
    description: str | None = None


class ServerInfo(BaseModel):
    name: str = "gke-cred-audit"
    version: str
    deployment: str = "natoma"
    auth: str = "none (gateway-managed)"
    raw_reveal_enabled: bool = False
    secret_listing_enabled: bool = False
    tools: list[ServerInfoTool] = Field(default_factory=list)
    resources: list[ServerInfoResource] = Field(default_factory=list)
