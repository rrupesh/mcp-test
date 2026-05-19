"""Stable ASGI entrypoint.

Importable as `gke_cred_audit.asgi:app`. Keeps the door open for the Python
source build path on Natoma (Procfile + uvicorn) without touching the
Dockerfile-managed runtime.

    uvicorn gke_cred_audit.asgi:app --host 0.0.0.0 --port "$PORT" \
        --proxy-headers --forwarded-allow-ips="*"
"""
from __future__ import annotations

from .api import create_app
from .config import Config

app = create_app(Config.from_env())
