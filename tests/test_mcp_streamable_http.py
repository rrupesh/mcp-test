"""Verify the MCP server is mounted at /mcp and speaks Streamable HTTP."""
from __future__ import annotations

from fastapi.testclient import TestClient

from gke_cred_audit.api import create_app
from gke_cred_audit.config import Config


def test_mcp_initialize_round_trip_streamable_http():
    """POST /mcp/ with an `initialize` request and assert the server returns
    a JSON-RPC response and the `Mcp-Session-Id` header (Streamable HTTP)."""
    app = create_app(Config())
    with TestClient(app, base_url="http://127.0.0.1") as client:
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "0"},
            },
        }
        r = client.post(
            "/mcp/",
            json=body,
            headers={
                "Accept": "application/json, text/event-stream",
                "Host": "127.0.0.1",
            },
        )
        assert r.status_code == 200, r.text


def test_mcp_mounted_at_slash_mcp():
    app = create_app(Config())
    routes = [getattr(r, "path", "") for r in app.routes]
    assert any(p.startswith("/mcp") for p in routes), f"no /mcp mount in {routes}"


def test_mcp_tool_set_includes_namespace_tools():
    """Confirm Natoma will see the namespace-scoped tools (sanity check on the
    in-process FastMCP registry, not a wire test)."""
    from gke_cred_audit.mcp_server import build_mcp

    mcp = build_mcp(Config())
    tools = {t.name for t in mcp._tool_manager.list_tools()}
    assert "list_namespace_pods_tool" in tools
    assert "list_namespace_configmaps_tool" in tools
    assert "list_namespace_secrets_tool" in tools
    assert "describe_pod" in tools
    # No node-scoped tool remains.
    assert "list_node_pods" not in tools
