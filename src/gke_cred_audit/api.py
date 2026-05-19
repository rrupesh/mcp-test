"""FastAPI application + MCP Streamable HTTP mount."""
from __future__ import annotations

import contextlib
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response

from . import __version__
from .audit import run_audit
from .collectors.gcp_metadata import GcpMetadataClient
from .collectors.k8s_namespace import (
    collect_namespace,
    list_namespace_configmaps,
    list_namespace_pods,
    list_namespace_secrets,
)
from .config import Config
from .mcp_server import _server_info, build_mcp
from .models import (
    ConfigMapMeta,
    CredentialInventory,
    FindingList,
    MetadataValue,
    NamespacePosture,
    PodPosture,
    Problem,
    RbacReport,
    Report,
    SecretMeta,
    ServerInfo,
    Severity,
)
from .openapi import build_openapi


def _problem(status: int, title: str, detail: str | None = None) -> JSONResponse:
    body = Problem(title=title, status=status, detail=detail).model_dump(exclude_none=True)
    return JSONResponse(status_code=status, content=body, media_type="application/problem+json")


_DEFAULT_RESPONSES: dict[int | str, dict[str, Any]] = {
    400: {"model": Problem, "description": "Bad request"},
    404: {"model": Problem, "description": "Not found"},
    500: {"model": Problem, "description": "Internal server error"},
}


def create_app(cfg: Config | None = None) -> FastAPI:
    cfg = cfg or Config.from_env()
    mcp = build_mcp(cfg)
    # The inner Streamable HTTP app defaults to serving its handler at `/mcp`.
    # We mount that app at `/mcp` on FastAPI, so collapse the inner path to "/".
    mcp.settings.streamable_http_path = "/"

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        async with mcp.session_manager.run():
            yield

    app = FastAPI(
        title="gke-cred-audit",
        version=__version__,
        lifespan=lifespan,
        openapi_url="/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
    )
    app.state.cfg = cfg

    @app.get("/healthz", tags=["health"], summary="Liveness probe")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", tags=["health"], summary="Readiness probe")
    async def readyz() -> dict[str, str]:
        return {"status": "ready"}

    @app.get("/version", tags=["health"], summary="Build info and runtime mode")
    async def version() -> dict[str, Any]:
        return {
            "version": __version__,
            "deployment": "natoma",
            "auth": "none (gateway-managed)",
            "raw_reveal_enabled": cfg.raw_reveal,
            "secret_listing_enabled": cfg.enable_secret_listing,
        }

    @app.get(
        "/server-info",
        tags=["health"],
        summary="Server capability manifest (mirror of audit://server-info MCP resource)",
        response_model=ServerInfo,
    )
    async def server_info() -> ServerInfo:
        return _server_info(cfg, mcp)

    @app.get(
        "/report",
        tags=["report"],
        summary="Full audit report",
        response_model=Report,
        responses=_DEFAULT_RESPONSES,
    )
    async def report() -> Report:
        return await run_audit(cfg)

    @app.get(
        "/credentials",
        tags=["report"],
        summary="Credential inventory only (redacted)",
        response_model=CredentialInventory,
        responses=_DEFAULT_RESPONSES,
    )
    async def credentials() -> CredentialInventory:
        return (await run_audit(cfg)).credentials

    @app.get(
        "/rbac",
        tags=["report"],
        summary="RBAC posture (SSRR + SSAR)",
        response_model=RbacReport,
        responses=_DEFAULT_RESPONSES,
    )
    async def rbac() -> RbacReport:
        return (await run_audit(cfg)).rbac

    @app.get(
        "/findings",
        tags=["findings"],
        summary="Severity-tagged findings",
        response_model=FindingList,
        responses=_DEFAULT_RESPONSES,
    )
    async def findings(severity: Severity | None = Query(default=None)) -> FindingList:
        rep = await run_audit(cfg)
        if severity is None:
            return rep.findings
        return FindingList(items=[f for f in rep.findings.items if f.severity == severity])

    @app.get(
        "/metadata/{path:path}",
        tags=["metadata"],
        summary="Read a GCE metadata path (auto-redacted)",
        response_model=MetadataValue,
        responses=_DEFAULT_RESPONSES,
    )
    async def metadata(path: str) -> MetadataValue:
        client = GcpMetadataClient(cfg)
        try:
            return await client.describe("/" + path)
        finally:
            await client.aclose()

    @app.get(
        "/namespace",
        tags=["namespace"],
        summary="Namespace posture (pods + configmaps + secret-meta when enabled)",
        response_model=NamespacePosture,
        responses=_DEFAULT_RESPONSES,
    )
    async def namespace() -> NamespacePosture:
        return await collect_namespace(cfg)

    @app.get(
        "/namespace/pods",
        tags=["namespace"],
        summary="Pods in this pod's namespace",
        response_model=list[PodPosture],
        responses=_DEFAULT_RESPONSES,
    )
    async def namespace_pods() -> list[PodPosture]:
        return await list_namespace_pods(cfg)

    @app.get(
        "/namespace/pods/{name}",
        tags=["namespace"],
        summary="Posture for a specific pod by name",
        response_model=PodPosture,
        responses=_DEFAULT_RESPONSES,
    )
    async def namespace_pod(name: str) -> PodPosture:
        for p in await list_namespace_pods(cfg):
            if p.name == name:
                return p
        raise HTTPException(status_code=404, detail=f"pod {name!r} not found in this namespace")

    @app.get(
        "/namespace/configmaps",
        tags=["namespace"],
        summary="ConfigMap metadata in this namespace",
        response_model=list[ConfigMapMeta],
        responses=_DEFAULT_RESPONSES,
    )
    async def namespace_configmaps() -> list[ConfigMapMeta]:
        return await list_namespace_configmaps(cfg)

    @app.get(
        "/namespace/secrets",
        tags=["namespace"],
        summary="Secret metadata (values never returned). 404 when secret listing is disabled.",
        response_model=list[SecretMeta],
        responses=_DEFAULT_RESPONSES,
    )
    async def namespace_secrets() -> list[SecretMeta]:
        result = await list_namespace_secrets(cfg)
        if result is None:
            raise HTTPException(
                status_code=404,
                detail="secret listing disabled (set AUDIT_ENABLE_SECRET_LISTING=true to enable)",
            )
        return result

    @app.exception_handler(HTTPException)
    async def http_exc(_req: Request, exc: HTTPException) -> Response:
        return _problem(exc.status_code, exc.__class__.__name__, str(exc.detail))

    # Mount MCP Streamable HTTP at /mcp.
    app.mount("/mcp", mcp.streamable_http_app())

    app.openapi = lambda: build_openapi(app)  # type: ignore[assignment]
    return app
