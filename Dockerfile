# Stage 1: Builder
# python:3.9 reached EOL Oct 2025 and Debian 11 "bullseye" is LTS-only;
# bumped to a current, digest-pinned base (3.12-slim-bookworm, matching
# .github/workflows/ci.yml's test interpreter). Digest fetched live from
# the registry on 2026-09-05 -- re-pin periodically (Renovate/Dependabot)
# rather than letting this go stale the way the tag-only pin did.
FROM python:3.14-slim-bookworm@sha256:9ab8d9c8514b44f90cf0029dd42fdd7e9e211e639c8b995304cc04568dee900f AS builder
RUN apt-get update && apt-get install -y --no-install-recommends build-essential
WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt
# jsonschema and python-dateutil are now in requirements.txt itself (they
# used to be missing entirely, hence this separate install); only the
# Faust C-accelerator remains here since it isn't in the production deps.
RUN pip install --user --no-cache-dir faust-cchardet

# Stage 2: Production
FROM python:3.14-slim-bookworm@sha256:9ab8d9c8514b44f90cf0029dd42fdd7e9e211e639c8b995304cc04568dee900f
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
# Pins the --user install's real location independently of $HOME -- see
# Dockerfile.dashboard's identical line for why: Python re-derives its
# "user site-packages" path from $HOME at every interpreter startup, not
# from where the packages actually live, so a future HOME override on
# any workload built from this image (e.g. to satisfy
# readOnlyRootFilesystem, the way k8s/soc-deployment.yaml's dashboard
# container already needed) would otherwise silently break every
# --user-installed import.
ENV PYTHONPATH=/home/soc_user/.local/lib/python3.12/site-packages
COPY --chown=soc_user:soc_user . .
USER soc_user
ENV PYTHONUNBUFFERED=1
# HEALTHCHECK instruction added for Docker runtime resilience
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD curl -f http://localhost:6066/healthz || curl -f http://localhost:8000/healthz || exit 1
CMD ["python", "inference/stream_processor_faust.py", "worker", "-l", "info"]
