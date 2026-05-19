"""OpenAPI 3.1 customizations."""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from . import __version__


def build_openapi(app: FastAPI) -> dict[str, Any]:
    schema = get_openapi(
        title="gke-cred-audit",
        version=__version__,
        summary="Defensive credential-exposure auditor for GKE pods.",
        description=(
            "Read-only API for inventorying credentials and RBAC the local pod (or, in DaemonSet "
            "mode, the local node) is exposed to. Tokens are redacted by default; the response "
            "schemas only carry claims, scopes, expiries, and SHA-256 prefixes."
        ),
        routes=app.routes,
        contact={"name": "Security Platform"},
        license_info={"name": "Apache-2.0"},
    )
    schema["openapi"] = "3.1.0"
    schema.setdefault("servers", [{"url": "http://gke-cred-audit:8787"}])
    schema["x-deployment"] = "natoma"
    schema["x-auth"] = "none (gateway-managed)"
    schema.setdefault("tags", [
        {"name": "health", "description": "Liveness, readiness, and server-info."},
        {"name": "report", "description": "Full inventory and per-section reads."},
        {"name": "findings", "description": "Severity-tagged remediation items."},
        {"name": "metadata", "description": "Read GCE metadata service paths (auto-redacted)."},
        {"name": "namespace", "description": "Pods/ConfigMaps/Secrets metadata in this pod's namespace."},
    ])
    return schema
