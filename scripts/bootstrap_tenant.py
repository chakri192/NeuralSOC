#!/usr/bin/env python3
"""bootstrap_tenant.py -- creates a tenant's first admin account and an
ingest sensor token for it, via the real API (not a direct database
write). This is the one path around the auth system's own
chicken-and-egg problem: /auth/login needs an existing user, and the
invite endpoint (POST .../users/invite) needs an existing admin to call
it -- POST /auth/signup needs neither, which is exactly why it exists.

Local dev / demo (matches the Quickstart in README.md):
    PYTHONPATH=. venv/bin/python3 scripts/bootstrap_tenant.py

Against a real deployment:
    PYTHONPATH=. venv/bin/python3 scripts/bootstrap_tenant.py \
        --api-url https://api.tsoc.example/api/v1 \
        --tenant-name "Acme Corp" --email admin@acme.example.com

Prints the admin login and a TSOC_SENSOR_TOKEN value ready to export
for `make kafka-sink` / api/kafka_sink.py. Nothing here is idempotent
by design (every run either creates a new tenant+admin, or -- if the
email already exists -- fails loudly rather than silently reusing
someone else's account) -- run it once per tenant.
"""
import argparse
import secrets
import sys

import requests

_DEFAULT_API_URL = "http://127.0.0.1:8000/api/v1"
_REQUEST_TIMEOUT_SEC = 10


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap a tenant's first admin account and ingest sensor token")
    parser.add_argument("--api-url", default=_DEFAULT_API_URL, help=f"default: {_DEFAULT_API_URL}")
    parser.add_argument("--tenant-name", default="Demo Tenant")
    parser.add_argument("--email", default="admin@demo.local")
    parser.add_argument("--password", default=None, help="generated randomly if omitted")
    parser.add_argument("--sensor-name", default="Local dev sensor", help="label for the minted ingest token")
    args = parser.parse_args()

    password = args.password or secrets.token_urlsafe(12)

    signup = requests.post(
        f"{args.api_url}/auth/signup",
        json={"tenant_name": args.tenant_name, "email": args.email, "password": password},
        timeout=_REQUEST_TIMEOUT_SEC,
    )
    if signup.status_code == 409:
        print(f"A user with email {args.email!r} already exists -- log in instead of bootstrapping again.", file=sys.stderr)
        return 1
    signup.raise_for_status()
    body = signup.json()
    admin_token, tenant_id = body["access_token"], body["tenant_id"]

    sensor = requests.post(
        f"{args.api_url}/ingest/tenants/{tenant_id}/sensor-tokens",
        json={"name": args.sensor_name},
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=_REQUEST_TIMEOUT_SEC,
    )
    sensor.raise_for_status()
    sensor_token = sensor.json()["token"]

    print("Tenant and admin account created.\n")
    print(f"  Tenant:            {args.tenant_name} (id={tenant_id})")
    print(f"  Admin email:       {args.email}")
    if not args.password:
        print(f"  Admin password:    {password}  (generated -- save it, it won't be shown again)")
    print("\nExport this before running `make kafka-sink` (or set it in .env):\n")
    print(f"  export TSOC_SENSOR_TOKEN={sensor_token}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
