# Stage 1: Builder
# python:3.9 reached EOL Oct 2025 and Debian 11 "bullseye" is LTS-only;
# bumped to a current, digest-pinned base (3.12-slim-bookworm, matching
# .github/workflows/ci.yml's test interpreter). Digest fetched live from
# the registry on 2026-09-05 -- re-pin periodically (Renovate/Dependabot)
# rather than letting this go stale the way the tag-only pin did.
FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends build-essential
WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt
# jsonschema and python-dateutil are now in requirements.txt itself (they
# used to be missing entirely, hence this separate install); only the
# Faust C-accelerator remains here since it isn't in the production deps.
RUN pip install --user --no-cache-dir faust-cchardet

# Stage 2: Production
FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254
# curl is for the HEALTHCHECK below, which matters for `docker compose up`/
# local `docker run` (k8s ignores Docker HEALTHCHECK -- it uses the
# manifests' own liveness/readiness probes instead).
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
# --uid 1000 pinned explicitly: k8s/soc-deployment.yaml hardcodes
# securityContext.runAsUser: 1000 on every workload. Without pinning here,
# a base-image change that happens to pre-create a UID-1000 user shifts
# soc_user to 1001, and the pod then runs as a UID that owns none of the
# files COPY --chown=soc_user:soc_user below just placed.
RUN useradd --create-home --no-log-init --uid 1000 soc_user
WORKDIR /app
COPY --from=builder /root/.local /home/soc_user/.local
ENV PATH=/home/soc_user/.local/bin:$PATH
COPY --chown=soc_user:soc_user . .
USER soc_user
ENV PYTHONUNBUFFERED=1
# HEALTHCHECK instruction added for Docker runtime resilience
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD curl -f http://localhost:6066/healthz || curl -f http://localhost:8000/healthz || exit 1
CMD ["python", "inference/stream_processor_faust.py", "worker", "-l", "info"]
