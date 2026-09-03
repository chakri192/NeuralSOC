import re

with open("inference/models.py", "r") as f:
    code = f.read()

# Replace silent mock fallback with a strict crash
old_except = """        except Exception as e:
            logger.error(f"[!] DGA Model load failed: {e}. Falling back to heuristics.")
            self.mock_mode = True"""

new_except = """        except Exception as e:
            logger.error(f"[!] CRITICAL: DGA Model integrity verification failed: {e}.")
            raise RuntimeError("Enterprise Security Guard: Halting pipeline due to compromised or missing PyTorch weights. Ensure .sha256 signature is valid.")"""

code = code.replace(old_except, new_except)

with open("inference/models.py", "w") as f:
    f.write(code)
