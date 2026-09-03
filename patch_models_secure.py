with open("inference/models.py", "r") as f:
    code = f.read()

# Add weights_only=True to torch.jit.load
if "torch.jit.load(" in code and "weights_only=" not in code:
    # torch.jit.load doesn't actually take weights_only, torch.load does.
    # Wait, the audit said: `torch.load without weights_only=True; deserialization risk remains in models.py:47`.
    # Let me check if line 47 is torch.jit.load or torch.load.
    pass
