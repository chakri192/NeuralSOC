#!/usr/bin/env python3
"""Sign a model artifact with a persistent Ed25519 key.

Previously generated a FRESH keypair on every invocation, signed with it,
then wrote the public key into the SAME manifest file as the signature --
which proves nothing an attacker couldn't also produce (regenerate a new
throwaway key, re-sign, ship both together). A signature is only
meaningful when the verifier's copy of the public key comes from a
channel the signer doesn't control.

This script is not wired into anything yet (confirmed: no CI step, no
other script references it) and nothing in this repo currently ships a
real, persistent private key or a trusted distribution channel for the
public key -- that requires real KMS/Vault/Sigstore infrastructure this
environment doesn't have. Until that exists, this script refuses to run
rather than produce a self-signed manifest that looks like a real
integrity guarantee.
"""
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

MANIFEST = "models/manifest.json"


def _load_persistent_private_key() -> ed25519.Ed25519PrivateKey:
    raw_hex = os.environ.get("MODEL_SIGNING_PRIVATE_KEY")
    if not raw_hex:
        raise RuntimeError(
            "MODEL_SIGNING_PRIVATE_KEY not set. This script will not "
            "generate a throwaway key -- that proves nothing. Provision a "
            "real, persistent Ed25519 key (KMS/Vault-backed in "
            "production) and distribute its PUBLIC half to verifiers "
            "through a channel this signer does not control (e.g. baked "
            "into the deployed image or a separately-managed ConfigMap) "
            "-- never read the public key back out of this manifest."
        )
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw_hex))


def sign_artifact(path="models/cnn_dga.pt"):
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    private_key = _load_persistent_private_key()
    manifest = {
        "artifact": os.path.basename(path),
        "sha256": digest,
        "sig": private_key.sign(digest.encode()).hex(),
        # No "pubkey" field: a verifier must already have the public key
        # from a trusted source, never from this same file.
    }
    with open(MANIFEST, "w") as f:
        json.dump(manifest, f)
    return manifest


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "models/cnn_dga.pt"
    result = sign_artifact(target)
    print(f"Signed {target}: sha256={result['sha256']}")
