#!/usr/bin/env bash
# generate_dev_certs.sh — self-signed TLS material for the local Redis
# container (docker-compose.yml's redis service mounts ./certs into
# /certs and requires redis.crt/redis.key/ca.crt to start at all).
#
# Local development only. Production deploys inject real certs via
# Vault/cert-manager — see k8s/secrets.yaml.example and k8s/ingress.yaml.
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")/.." && pwd)/certs"
mkdir -p "$CERT_DIR"

if [[ -f "$CERT_DIR/redis.crt" && -f "$CERT_DIR/redis.key" && -f "$CERT_DIR/ca.crt" && -f "$CERT_DIR/client.crt" && -f "$CERT_DIR/client.key" ]]; then
    echo "==> certs/ already populated; remove $CERT_DIR to regenerate."
    exit 0
fi

echo "==> Generating a self-signed CA and Redis server cert into $CERT_DIR"

openssl genrsa -out "$CERT_DIR/ca.key" 4096 2>/dev/null
openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" -sha256 -days 3650 \
    -subj "/CN=tsoc-dev-ca" -out "$CERT_DIR/ca.crt"

openssl genrsa -out "$CERT_DIR/redis.key" 2048 2>/dev/null
openssl req -new -key "$CERT_DIR/redis.key" \
    -subj "/CN=soc-redis" -out "$CERT_DIR/redis.csr"
openssl x509 -req -in "$CERT_DIR/redis.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/redis.crt" -days 3650 -sha256 \
    -extfile <(printf "subjectAltName=DNS:soc-redis,DNS:localhost,IP:127.0.0.1")

# Client cert: presented by api/deps.py and inference/correlation.py so
# redis-server's --tls-auth-clients yes (docker-compose.yml) can verify
# the caller, not just encrypt the channel. One shared cert for both
# consumers -- there's no per-service authorization distinction on the
# Redis side here to justify separate identities for local dev.
openssl genrsa -out "$CERT_DIR/client.key" 2048 2>/dev/null
openssl req -new -key "$CERT_DIR/client.key" \
    -subj "/CN=tsoc-redis-client" -out "$CERT_DIR/client.csr"
openssl x509 -req -in "$CERT_DIR/client.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/client.crt" -days 3650 -sha256

rm -f "$CERT_DIR/redis.csr" "$CERT_DIR/client.csr" "$CERT_DIR/ca.srl"
# ca.key is never read by anything except this script (it only signs
# redis.key at generation time, here, on the host) -- kept as owner-only.
chmod 600 "$CERT_DIR/ca.key"
# redis.key IS read at runtime, by redis-server inside the container via
# the ./certs:/certs:ro bind mount. chmod 600 (owner-only, i.e. whichever
# host user ran this script) worked under Docker Desktop's VM-mediated
# filesystem on macOS, where UID enforcement across the host/container
# boundary is not the same as a native Linux Docker host -- confirmed
# directly: CI's integration-smoke-test job failed with "Failed to load
# private key: /certs/redis.key: ... Permission denied" the moment this
# ran on a real ubuntu-latest runner. redis.key is a throwaway,
# self-signed, local-dev-only credential with no production value (see
# header above) -- not the kind of secret worth chasing exact
# container-UID alignment for. World-readable is an acceptable trade for
# working identically on every Docker host.
chmod 644 "$CERT_DIR/redis.key"
# client.key, unlike redis.key, is only ever read by whatever host process
# generated it (api/inference run as bare `make api`/`make pipeline`
# processes, not containers -- see README) -- no Docker UID boundary to
# cross, so the stricter owner-only default is safe here.
chmod 600 "$CERT_DIR/client.key"
echo "==> Done. docker compose up can now start the redis service."
