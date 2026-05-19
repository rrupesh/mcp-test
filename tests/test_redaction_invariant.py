"""Property-style invariant: no raw token bytes and no Secret values appear
in any REST or MCP response, including when secret enumeration is enabled.
"""
from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from gke_cred_audit.api import create_app
from gke_cred_audit.config import Config


# Realistic-looking bearer material; none of these bytes may appear in any response.
RAW_JWT = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJodHRwczovL2lzc3Vlci8iLCJzdWIiOiJzZWNyZXR5LXN1YiIsImF1ZCI6Imh0dHBzOi8vYXVkLyJ9."
    "ZmFrZS1zaWctc2VjcmV0Yml0c19BQkNERUYxMjM0NTY3ODkwc2VjcmV0c2lnbmF0dXJlcGF5bG9hZA"
)
RAW_OPAQUE = "ya29.SECRET_OPAQUE_GOOGLE_TOKEN_DO_NOT_LEAK_0123456789ABCDEFGHIJKLMN"
SECRET_VALUE_DECODED = b"super-secret-postgres-password-DO-NOT-LEAK"
SECRET_VALUE_B64 = base64.b64encode(SECRET_VALUE_DECODED).decode()


@pytest.fixture
def fake_pod_files(tmp_path):
    sa_dir = tmp_path / "sa"
    sa_dir.mkdir()
    (sa_dir / "token").write_text(RAW_JWT)
    (sa_dir / "ca.crt").write_text("-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n")
    (sa_dir / "namespace").write_text("test-ns")
    extra_secret_dir = tmp_path / "extra"
    extra_secret_dir.mkdir()
    (extra_secret_dir / "key.pem").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n" + RAW_OPAQUE + "\n-----END RSA PRIVATE KEY-----\n"
    )
    return sa_dir, extra_secret_dir


def _cfg(fake_pod_files, *, enable_secret_listing: bool) -> Config:
    sa_dir, extra_dir = fake_pod_files
    return Config(
        bind="127.0.0.1",
        port=0,
        metadata_host="http://mds.invalid",
        k8s_api="https://kapi.invalid",
        k8s_token_path=str(sa_dir / "token"),
        k8s_ca_path=str(sa_dir / "ca.crt"),
        k8s_namespace_path=str(sa_dir / "namespace"),
        secret_roots=(str(sa_dir.parent / "sa"), str(extra_dir)),
        identity_audience=None,
        enable_secret_listing=enable_secret_listing,
    )


def _walk_strings(obj: Any) -> list[str]:
    out: list[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_walk_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_walk_strings(v))
    return out


def _assert_no_raw_in(payload: Any) -> None:
    blob = json.dumps(payload)
    assert RAW_JWT not in blob, "raw JWT leaked"
    assert RAW_OPAQUE not in blob, "raw opaque token leaked"
    assert RAW_JWT.split(".")[2] not in blob, "JWT signature leaked"
    assert SECRET_VALUE_B64 not in blob, "Secret value (base64) leaked"
    assert SECRET_VALUE_DECODED.decode() not in blob, "Secret value (decoded) leaked"


def _mock_metadata(base: str) -> None:
    respx.get(f"{base}/computeMetadata/v1beta1/project/project-id").mock(return_value=httpx.Response(403))
    respx.get(f"{base}/computeMetadata/v1/project/project-id").mock(return_value=httpx.Response(200, text="proj-1"))
    respx.get(f"{base}/computeMetadata/v1/project/numeric-project-id").mock(return_value=httpx.Response(200, text="42"))
    respx.get(f"{base}/computeMetadata/v1/instance/id").mock(return_value=httpx.Response(200, text="123"))
    respx.get(f"{base}/computeMetadata/v1/instance/name").mock(return_value=httpx.Response(200, text="node-1"))
    respx.get(f"{base}/computeMetadata/v1/instance/zone").mock(
        return_value=httpx.Response(200, text="projects/42/zones/us-central1-a")
    )
    respx.get(f"{base}/computeMetadata/v1/instance/machine-type").mock(
        return_value=httpx.Response(200, text="projects/42/machineTypes/e2-small")
    )
    respx.get(f"{base}/computeMetadata/v1/instance/hostname").mock(return_value=httpx.Response(200, text="node-1"))
    respx.get(f"{base}/computeMetadata/v1/instance/attributes/").mock(
        return_value=httpx.Response(200, text="cluster-name\nkube-env\n")
    )
    respx.get(f"{base}/computeMetadata/v1/instance/service-accounts/").mock(
        return_value=httpx.Response(200, text="default/\n")
    )
    respx.get(
        f"{base}/computeMetadata/v1/instance/service-accounts/default/token?recursive=true&alt=json"
    ).mock(
        return_value=httpx.Response(
            200, json={"access_token": RAW_OPAQUE, "expires_in": 3599, "token_type": "Bearer"}
        )
    )
    respx.get(f"{base}/computeMetadata/v1/instance/service-accounts/default/email").mock(
        return_value=httpx.Response(200, text="sa@proj-1.iam.gserviceaccount.com")
    )
    respx.get(f"{base}/computeMetadata/v1/instance/service-accounts/default/scopes").mock(
        return_value=httpx.Response(200, text="https://www.googleapis.com/auth/cloud-platform\n")
    )


def _mock_k8s_default() -> None:
    respx.post("https://kapi.invalid/apis/authorization.k8s.io/v1/selfsubjectrulesreviews").mock(
        return_value=httpx.Response(
            200, json={"status": {"resourceRules": [], "nonResourceRules": [], "incomplete": False}}
        )
    )
    respx.post("https://kapi.invalid/apis/authorization.k8s.io/v1/selfsubjectaccessreviews").mock(
        return_value=httpx.Response(200, json={"status": {"allowed": False}})
    )
    respx.get("https://kapi.invalid/api/v1/namespaces/test-ns/pods").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    respx.get("https://kapi.invalid/api/v1/namespaces/test-ns/configmaps").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    respx.get("https://kapi.invalid/api/v1/namespaces/test-ns/secrets").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "metadata": {"name": "db-creds", "namespace": "test-ns"},
                        "type": "Opaque",
                        "data": {"password": SECRET_VALUE_B64, "username": base64.b64encode(b"appuser").decode()},
                    }
                ]
            },
        )
    )


@respx.mock
def test_rest_responses_never_contain_raw_tokens(fake_pod_files):
    cfg = _cfg(fake_pod_files, enable_secret_listing=False)
    _mock_metadata("http://mds.invalid")
    _mock_k8s_default()

    app = create_app(cfg)
    with TestClient(app) as client:
        for path in [
            "/report",
            "/credentials",
            "/rbac",
            "/findings",
            "/findings?severity=HIGH",
            "/metadata/computeMetadata/v1/project/project-id",
            "/metadata/computeMetadata/v1/instance/service-accounts/default/token",
            "/namespace",
            "/namespace/pods",
            "/namespace/configmaps",
            "/version",
            "/server-info",
        ]:
            r = client.get(path)
            assert r.status_code == 200, f"{path}: {r.status_code} {r.text}"
            _assert_no_raw_in(r.json())

        # /namespace/secrets is 404 when listing is disabled.
        r = client.get("/namespace/secrets")
        assert r.status_code == 404


@respx.mock
def test_secret_values_never_leak_when_listing_enabled(fake_pod_files):
    cfg = _cfg(fake_pod_files, enable_secret_listing=True)
    _mock_metadata("http://mds.invalid")
    _mock_k8s_default()

    app = create_app(cfg)
    with TestClient(app) as client:
        r = client.get("/namespace/secrets")
        assert r.status_code == 200, r.text
        body = r.json()
        # Each Secret carries name/type/keys; no value bytes appear anywhere.
        assert body[0]["name"] == "db-creds"
        assert {k["name"] for k in body[0]["keys"]} == {"password", "username"}
        # The metadata correctly reports the size and sha256 prefix.
        password_meta = next(k for k in body[0]["keys"] if k["name"] == "password")
        assert password_meta["size"] == len(SECRET_VALUE_DECODED)
        _assert_no_raw_in(body)

        # Whole report also clean.
        r = client.get("/report")
        assert r.status_code == 200
        _assert_no_raw_in(r.json())
