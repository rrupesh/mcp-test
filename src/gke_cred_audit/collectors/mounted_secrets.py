"""Compatibility shim. Mounted-secret walking lives in k8s_sa_tokens.

Kept as a separate import path so future changes (e.g. independent walkers
for /etc/secrets vs projected tokens) don't break callers.
"""
from .k8s_sa_tokens import _walk_secret_files as walk_secret_files  # noqa: F401
