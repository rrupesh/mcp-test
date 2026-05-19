"""Verify the Natoma deploy contract: default 0.0.0.0:8080, $PORT override,
and a stable ASGI app importable as `gke_cred_audit.asgi:app`.
"""
from __future__ import annotations

import importlib

from gke_cred_audit.config import Config


def test_default_bind_and_port():
    cfg = Config()
    assert cfg.bind == "0.0.0.0"
    assert cfg.port == 8080


def test_port_env_overrides(monkeypatch):
    monkeypatch.setenv("PORT", "9090")
    monkeypatch.delenv("AUDIT_PORT", raising=False)
    cfg = Config.from_env()
    assert cfg.port == 9090


def test_audit_port_used_when_no_port_env(monkeypatch):
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.setenv("AUDIT_PORT", "7070")
    cfg = Config.from_env()
    assert cfg.port == 7070


def test_port_env_takes_precedence_over_audit_port(monkeypatch):
    monkeypatch.setenv("PORT", "9090")
    monkeypatch.setenv("AUDIT_PORT", "7070")
    cfg = Config.from_env()
    assert cfg.port == 9090


def test_asgi_app_importable():
    """The Python-source-build path on Natoma uses `module:application`. Even
    though we deploy via Dockerfile today, ensure the ASGI shim works so the
    fallback is one Procfile away.
    """
    mod = importlib.import_module("gke_cred_audit.asgi")
    assert mod.app is not None
    # Sanity: the FastAPI instance has the expected routes mounted.
    paths = {getattr(r, "path", "") for r in mod.app.routes}
    assert "/healthz" in paths
    assert any(p.startswith("/mcp") for p in paths)
