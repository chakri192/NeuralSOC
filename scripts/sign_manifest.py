#!/usr/bin/env python3
"""Sign model artifact with Ed25519 manifest for immutable reference."""
import os, hashlib, base64
from cryptography.hazmat.primitives.asymmetric import ed25519

MANIFEST = "models/manifest.json"

def sign_artifact(path="models/cnn_dga.pt"):
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    private_key = ed25519.Ed25519PrivateKey.generate()
    manifest = {
        "artifact": os.path.basename(path),
        "sha256": digest,
        "pubkey": private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex(),
        "sig": private_key.sign(digest.encode()).hex()
    }
    with open(MANIFEST, "w") as f:
        json.dump(manifest, f)
    return manifest
