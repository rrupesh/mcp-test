"""OpenAPI 3.1 + Problem error-shape tests for the post-migration surface."""
from __future__ import annotations

import yaml
from openapi_spec_validator import validate

from gke_cred_audit.api import create_app
from gke_cred_audit.config import Config


EXPECTED_PATHS = {
    "/healthz",
    "/readyz",
    "/version",
    "/server-info",
    "/report",
    "/credentials",
    "/rbac",
    "/findings",
    "/metadata/{path}",
    "/namespace",
    "/namespace/pods",
    "/namespace/pods/{name}",
    "/namespace/configmaps",
    "/namespace/secrets",
}


def test_openapi_is_3_1_and_valid():
    app = create_app(Config())
    spec = app.openapi()
    assert spec["openapi"] == "3.1.0"
    validate(spec)
    assert spec["info"]["title"] == "gke-cred-audit"
    assert spec.get("x-deployment") == "natoma"
    assert spec.get("x-auth") == "none (gateway-managed)"
    assert EXPECTED_PATHS.issubset(set(spec["paths"].keys())), \
        f"missing: {EXPECTED_PATHS - set(spec['paths'].keys())}"


def test_openapi_yaml_snapshot_in_sync(tmp_path):
    app = create_app(Config())
    spec = app.openapi()
    out = tmp_path / "openapi.yaml"
    out.write_text(yaml.safe_dump(spec, sort_keys=False))
    parsed = yaml.safe_load(out.read_text())
    validate(parsed)
    assert parsed["openapi"] == "3.1.0"


def test_problem_response_attached_to_operations():
    app = create_app(Config())
    spec = app.openapi()
    responses = spec["paths"]["/findings"]["get"]["responses"]
    assert "404" in responses
    assert "$ref" in responses["404"]["content"]["application/json"]["schema"]
