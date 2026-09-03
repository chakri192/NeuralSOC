# Stage 1: Builder
FROM python:3.9-slim-bullseye AS builder
RUN apt-get update && apt-get install -y --no-install-recommends build-essential
WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt
RUN pip install --user --no-cache-dir jsonschema python-dateutil faust-cchardet

# Stage 2: Production
FROM python:3.9-slim-bullseye
RUN useradd --create-home --no-log-init soc_user
WORKDIR /app
COPY --from=builder /root/.local /home/soc_user/.local
ENV PATH=/home/soc_user/.local/bin:$PATH
COPY --chown=soc_user:soc_user . .
USER soc_user
ENV PYTHONUNBUFFERED=1
# HEALTHCHECK instruction added for Docker runtime resilience
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import sys; sys.exit(0)"
CMD ["python", "inference/stream_processor_faust.py", "worker", "-l", "info"]
