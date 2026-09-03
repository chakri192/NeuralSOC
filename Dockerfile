# Base Image for ARM64/Apple Silicon compatibility
FROM python:3.9-slim-bullseye

# Define build arguments for non-root execution
ARG UID=1000
ARG GID=1000

# Create a non-root user and group
RUN groupadd -g "${GID}" soc_group \
  && useradd --create-home --no-log-init -u "${UID}" -g "${GID}" soc_user

# Set working directory
WORKDIR /app

# Install system dependencies safely (removing package lists to reduce attack surface)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir jsonschema python-dateutil

# Copy application code with strict ownership
COPY --chown=soc_user:soc_group config/ ./config/
COPY --chown=soc_user:soc_group inference/ ./inference/
COPY --chown=soc_user:soc_group ingest/ ./ingest/

# Switch to the non-root user for all subsequent operations
USER soc_user

# Explicitly set environment bindings
ENV REDPANDA_BROKERS="soc-redpanda:29092"
ENV PYTHONUNBUFFERED=1

# Default execution falls back to the stream processor
CMD ["python", "inference/stream_processor.py"]
