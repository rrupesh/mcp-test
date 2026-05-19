# Multi-stage build for gke-cred-audit.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip build \
 && pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.12-slim
RUN useradd -u 65532 -m nonroot
WORKDIR /app
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
USER 65532
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8787/healthz', timeout=2)" || exit 1
ENTRYPOINT ["gke-cred-audit"]
CMD ["--bind", "127.0.0.1", "--port", "8787"]
