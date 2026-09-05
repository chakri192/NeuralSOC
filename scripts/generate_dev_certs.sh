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

if [[ -f "$CERT_DIR/redis.crt" && -f "$CERT_DIR/redis.key" && -f "$CERT_DIR/ca.crt" ]]; then
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

rm -f "$CERT_DIR/redis.csr" "$CERT_DIR/ca.srl"
chmod 600 "$CERT_DIR"/*.key
echo "==> Done. docker compose up can now start the redis service."
