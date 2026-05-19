# Multi-stage build for gke-cred-audit, deployable as a Natoma custom app.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip build \
 && pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/rrupesh/mcp-test"
LABEL org.opencontainers.image.title="gke-cred-audit"
LABEL org.opencontainers.image.description="Defensive credential-exposure auditor MCP server for GKE"
RUN useradd -u 65532 -m nonroot
WORKDIR /app
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
USER 65532

# Natoma forwards traffic to $PORT (default 8080). The server binds 0.0.0.0
# and reads PORT from the environment (with AUDIT_PORT fallback).
ENV AUDIT_BIND=0.0.0.0 \
    AUDIT_PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import os,urllib.request; p=os.environ.get('PORT') or os.environ.get('AUDIT_PORT') or '8080'; urllib.request.urlopen(f'http://127.0.0.1:{p}/healthz', timeout=2)" || exit 1

ENTRYPOINT ["gke-cred-audit"]
CMD []
