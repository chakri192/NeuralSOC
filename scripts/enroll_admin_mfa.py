#!/usr/bin/env python3
"""enroll_admin_mfa.py -- turns on TOTP MFA for an admin account via the
real API, printing the otpauth:// URI (scan it, or add the secret to an
authenticator app by hand) and confirming enrollment with a live code.

The only way to enable MFA today: dashboard/pages/admin.py (a general
"security settings" panel) doesn't exist yet, so this mirrors
scripts/bootstrap_tenant.py's role -- a CLI path to a capability that's
fully built and tested at the API layer before any UI catches up to it.

Usage:
    PYTHONPATH=. venv/bin/python3 scripts/enroll_admin_mfa.py \
        --email admin@acme.example.com --password '...'

Prompts for the password interactively if --password is omitted, rather
than leaving it in shell history. Prompts for the first live code from
your authenticator app to complete enrollment (api/routes/auth.py's
POST /auth/mfa/confirm) -- MFA does not actually gate login until that
succeeds.
"""
import argparse
import getpass
import sys

import requests

_DEFAULT_API_URL = "http://127.0.0.1:8000/api/v1"
_REQUEST_TIMEOUT_SEC = 10


def main() -> int:
    parser = argparse.ArgumentParser(description="Enroll an admin account in TOTP MFA")
    parser.add_argument("--api-url", default=_DEFAULT_API_URL, help=f"default: {_DEFAULT_API_URL}")
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", default=None, help="prompted for interactively if omitted")
    args = parser.parse_args()

    password = args.password or getpass.getpass("Password: ")

    login = requests.post(
        f"{args.api_url}/auth/login", json={"email": args.email, "password": password}, timeout=_REQUEST_TIMEOUT_SEC
    )
    if login.status_code == 429:
        print("Too many failed attempts. Try again later.", file=sys.stderr)
        return 1
    login.raise_for_status()
    body = login.json()
    if body.get("mfa_required"):
        print("MFA is already enabled for this account.", file=sys.stderr)
        return 1
    headers = {"Authorization": f"Bearer {body['access_token']}"}

    enroll = requests.post(f"{args.api_url}/auth/mfa/enroll", headers=headers, timeout=_REQUEST_TIMEOUT_SEC)
    if enroll.status_code == 403:
        print("MFA is admin-only -- this account doesn't hold the admin role.", file=sys.stderr)
        return 1
    enroll.raise_for_status()
    enrolled = enroll.json()

    print("\nScan this URI's QR code with an authenticator app (Google Authenticator, 1Password, etc.),")
    print("or add the secret manually if your app can't scan a URI directly.\n")
    print(f"  Secret:      {enrolled['secret']}")
    print(f"  otpauth URI: {enrolled['otpauth_uri']}\n")

    code = input("Enter the 6-digit code your authenticator app now shows: ").strip()
    confirm = requests.post(
        f"{args.api_url}/auth/mfa/confirm", json={"code": code}, headers=headers, timeout=_REQUEST_TIMEOUT_SEC
    )
    if confirm.status_code != 204:
        print(f"Code did not match -- MFA was NOT enabled ({confirm.status_code}: {confirm.text}).", file=sys.stderr)
        return 1

    print("\nMFA is now enabled. Every future login for this account needs a code from that")
    print("authenticator app in addition to the password.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
