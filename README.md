# gke-cred-audit

Defensive credential-exposure auditor for GKE. Deployed in-cluster as a single
Pod (Deployment + Service); fronted by Natoma at `/mcp`.

The server uses its own ServiceAccount to:

- Inventory **its own** GCE/GKE workload-identity exposure (project, instance, SA scopes/tokens).
- Decode **its own** projected ServiceAccount token (claims only) and walk its mounted secret files.
- Inventory the **pods + ConfigMaps** in its namespace (and, opt-in, **secret metadata**) so
  Natoma can ask follow-up questions about workloads that share the namespace.
- Compute its own RBAC posture via `SelfSubjectRulesReview` and a curated `SelfSubjectAccessReview` matrix.

## Surfaces

- **REST** with an OpenAPI 3.1 spec at `/openapi.json` (Swagger UI at `/docs`, ReDoc at `/redoc`).
- **MCP server** over **Streamable HTTP**, mounted at **`/mcp`** (per MCP spec rev 2025-03-26).

Both surfaces share the same redacted pydantic models. **Raw bearer tokens, JWT signatures, PEM
private keys, and Secret values are never returned.** The break-glass `RAW_REVEAL` flag exists for
debugging individual tokens; it never extends to namespace Secret values.

## Deploying via Natoma

Natoma is the auth boundary for `/mcp`. The server itself has no native auth; this is intentional
and surfaced in `/version`, `audit://server-info`, and the OpenAPI spec via `x-auth=none (gateway-managed)`.

### Dockerfile path (recommended)

This repo has a root `Dockerfile`. Point Natoma at this repo and it will build and run the
container. The server reads `$PORT` (default `8080`) and binds `0.0.0.0`. uvicorn is configured
with `--proxy-headers --forwarded-allow-ips="*"` so X-Forwarded-* from the gateway is honored.

### Direct cluster deployment

```
kubectl apply -f manifests/rbac.yaml
kubectl apply -f manifests/deployment.yaml
kubectl apply -f manifests/service.yaml
kubectl apply -f manifests/networkpolicy.yaml
```

Then point Natoma's gateway at `http://gke-cred-audit.<namespace>.svc:8080/mcp`.

The bundled `NetworkPolicy` only permits ingress from namespaces labeled `natoma-gateway: "true"`;
adjust to match your installation. Egress is restricted to the Kubernetes API server and the GCE
metadata IP.

## Granting secret enumeration

`AUDIT_ENABLE_SECRET_LISTING=true` opts in to namespace Secret enumeration. Even when enabled, the
server returns metadata only -- name, type, key names, per-key size, per-key SHA-256 prefix.
**Values are never returned.** A property-based test (`tests/test_redaction_invariant.py`)
runs against mocked Secrets containing real-looking base64 `data` to enforce this.

The trade-off: granting `secrets:list` to the audit ServiceAccount makes the audit pod a high-trust
target. Default is OFF. When enabling, prefer:

- A dedicated namespace for the audit Deployment, with no other workloads.
- Tightening the bundled Role with `resourceNames: [...]` to specific Secret names.
- A `NS-SECRETS-LIST-GRANTED` finding will appear in `/findings` to make this visible.

## Running locally

```
pip install -e '.[dev]'
gke-cred-audit --bind 127.0.0.1 --port 8080
```

Then:

- `curl http://127.0.0.1:8080/openapi.json` -- OpenAPI 3.1 document
- `curl http://127.0.0.1:8080/findings?severity=HIGH` -- JSON findings
- `curl http://127.0.0.1:8080/server-info` -- capability manifest
- MCP clients connect to `http://127.0.0.1:8080/mcp`

## What's intentionally NOT in scope

- Cross-namespace reads (would require ClusterRole; not used).
- Returning Secret `data`/`stringData` under any flag.
- Native auth on the server (Natoma owns auth).
