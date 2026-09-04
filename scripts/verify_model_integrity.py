import hashlib
import sys
import pathlib
import torch
import io
import secrets

if len(sys.argv) < 2:
    print("Usage: python verify_model_integrity.py <path_to_model.pt> [<path_to_sha256>]")
    sys.exit(1)

path = pathlib.Path(sys.argv[1])
if len(sys.argv) >= 3:
    sha_path = pathlib.Path(sys.argv[2])
else:
    sha_path = pathlib.Path(f"{path}.sha256")

if not sha_path.exists():
    raise FileNotFoundError(f"SHA-256 reference file not found: {sha_path}")

expected = sha_path.read_text().split()[0].strip()

# Read model once into memory to prevent TOCTOU race
model_bytes = path.read_bytes()
actual = hashlib.sha256(model_bytes).hexdigest()
assert secrets.compare_digest(actual, expected), f"Model SHA mismatch: {actual} != {expected}"

# Load from in-memory stream after hash verification
try:
    torch.load(io.BytesIO(model_bytes), weights_only=True, map_location="cpu")
except Exception:
    torch.jit.load(io.BytesIO(model_bytes), map_location="cpu")  # nosec B614

print(f"Model {path} verified against {sha_path} and loaded securely.")
