import hashlib
import sys
import pathlib
import torch

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
actual = hashlib.sha256(path.read_bytes()).hexdigest()
assert actual == expected, f"Model SHA mismatch: {actual} != {expected}"

# Load with weights_only=True for RCE prevention if standard PyTorch checkpoint, or JIT load
try:
    torch.load(str(path), weights_only=True, map_location="cpu")
except Exception:
    torch.jit.load(str(path), map_location="cpu")

print(f"Model {path} verified against {sha_path} and loaded securely.")
