"""Projected ServiceAccount token + mounted secret file walker."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from ..config import Config
from ..models import (
    JwtClaims,
    K8sCredentialInventory,
    MountedSecretFile,
    ProjectedSaToken,
)
from ..redact import decode_jwt_claims, looks_like_jwt, redact_token, sha256_prefix

_LOG = logging.getLogger("audit.k8s_sa_tokens")


def _detect_kind(sample: bytes) -> str:
    text = ""
    try:
        text = sample.decode("utf-8", errors="ignore")
    except Exception:
        return "opaque"
    head = text.lstrip()[:64]
    if "-----BEGIN" in head and "PRIVATE KEY" in head:
        return "pem-private-key"
    if head.startswith(("apiVersion:", "clusters:", "current-context:")):
        return "kubeconfig"
    stripped = text.strip()
    if looks_like_jwt(stripped):
        return "jwt"
    return "opaque"


def _walk_secret_files(roots: tuple[str, ...]) -> list[MountedSecretFile]:
    out: list[MountedSecretFile] = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
            for name in filenames:
                p = Path(dirpath) / name
                try:
                    if p.is_symlink() and not p.exists():
                        continue
                    st = p.stat()
                    if not p.is_file():
                        continue
                    with p.open("rb") as fh:
                        sample = fh.read(4096)
                    out.append(
                        MountedSecretFile(
                            path=str(p),
                            size=st.st_size,
                            sha256_prefix=sha256_prefix(sample),
                            kind=_detect_kind(sample),
                        )
                    )
                except (OSError, PermissionError) as exc:
                    _LOG.debug("skip %s: %s", p, exc)
    # Stable ordering for deterministic reports.
    out.sort(key=lambda f: f.path)
    return out


def _read_text(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except (OSError, UnicodeDecodeError):
        return None


def collect_k8s_credentials(cfg: Config) -> K8sCredentialInventory:
    projected = None
    namespace = _read_text(cfg.k8s_namespace_path)
    token = _read_text(cfg.k8s_token_path)
    if token:
        try:
            claims = decode_jwt_claims(token)
        except ValueError:
            claims = JwtClaims()
        projected = ProjectedSaToken(
            namespace=namespace,
            redaction=redact_token(token),
            claims=claims,
        )
    ca_present = os.path.isfile(cfg.k8s_ca_path)
    files = _walk_secret_files(cfg.secret_roots)
    return K8sCredentialInventory(
        projected_token=projected,
        ca_present=ca_present,
        mounted_secret_files=files,
    )
