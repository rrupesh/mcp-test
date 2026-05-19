"""Runtime configuration."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    bind: str = "0.0.0.0"
    port: int = 8787

    # GCE metadata
    metadata_host: str = "http://169.254.169.254"
    metadata_timeout_seconds: float = 1.5
    identity_audience: str | None = None

    # Kubernetes
    k8s_api: str = "https://kubernetes.default.svc"
    k8s_ca_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    k8s_token_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    k8s_namespace_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

    # Secret-walk roots (mounted secret files inside our own pod)
    secret_roots: tuple[str, ...] = ("/var/run/secrets", "/etc/secrets")

    # Namespace collector trade-offs
    enable_secret_listing: bool = False

    # Reveal gate (default OFF)
    raw_reveal: bool = False
    raw_reveal_header_secret: str | None = None

    @staticmethod
    def from_env() -> "Config":
        def _b(name: str, default: bool) -> bool:
            v = os.getenv(name)
            if v is None:
                return default
            return v.strip().lower() in {"1", "true", "yes", "on"}

        return Config(
            bind=os.getenv("AUDIT_BIND", "0.0.0.0"),
            port=int(os.getenv("AUDIT_PORT", "8787")),
            metadata_host=os.getenv("AUDIT_MDS_HOST", "http://169.254.169.254"),
            metadata_timeout_seconds=float(os.getenv("AUDIT_MDS_TIMEOUT", "1.5")),
            identity_audience=os.getenv("AUDIT_IDENTITY_AUDIENCE"),
            k8s_api=os.getenv("AUDIT_K8S_API", "https://kubernetes.default.svc"),
            enable_secret_listing=_b("AUDIT_ENABLE_SECRET_LISTING", False),
            raw_reveal=_b("AUDIT_RAW_REVEAL", False),
            raw_reveal_header_secret=os.getenv("AUDIT_RAW_REVEAL_SECRET"),
        )
