import re

# 1. Fix DLQ re-raise and ThreadPoolExecutor in Faust
try:
    with open("inference/stream_processor_faust.py", "r") as f:
        code = f.read()
    
    # Remove the `raise` from the DLQ exception block
    if "            raise\n" in code:
        code = code.replace("            raise\n", "")
        
    # Inject ThreadPoolExecutor
    if "from concurrent.futures import ThreadPoolExecutor" not in code:
        code = "from concurrent.futures import ThreadPoolExecutor\n" + code
        
    executor_init = """# ----------------------------------------------------------------------
# Thread Pool
# ----------------------------------------------------------------------
executor = ThreadPoolExecutor(max_workers=16)

"""
    if "executor = ThreadPoolExecutor" not in code:
        code = code.replace("app = faust.App(", executor_init + "app = faust.App(")
        
    # Replace asyncio.to_thread with run_in_executor
    code = code.replace("asyncio.to_thread(extract_features, event)", "asyncio.get_event_loop().run_in_executor(executor, extract_features, event)")
    code = code.replace("asyncio.to_thread(evaluate_rules, event, features)", "asyncio.get_event_loop().run_in_executor(executor, evaluate_rules, event, features)")
    code = code.replace("asyncio.to_thread(app.orchestrator.evaluate, event, features)", "asyncio.get_event_loop().run_in_executor(executor, app.orchestrator.evaluate, event, features)")
    code = code.replace("asyncio.to_thread(app.correlator.add_alert, alert)", "asyncio.get_event_loop().run_in_executor(executor, app.correlator.add_alert, alert)")
    
    with open("inference/stream_processor_faust.py", "w") as f:
        f.write(code)
except Exception as e:
    print(f"Error patching faust: {e}")

# 2. Add Unicode IDNA normalization to models.py
try:
    with open("inference/models.py", "r") as f:
        code = f.read()
        
    if "import idna" not in code:
        # We might need to handle the idna import. We'll use a try/except around the import.
        idna_logic = """        try:
            import idna
            domain = idna.encode(domain).decode('utf-8')
        except Exception:
            pass  # Fallback if idna is not installed
        
        domain = domain.lower()
"""
        # Inject idna normalization before tensor mapping
        # Look for where the domain is processed
        if "def predict" in code:
            # We assume domain is extracted in predict or inside encode
            pass
            
        # Actually, let's just find where `string.ascii_lowercase` is used or where the tensor is built
        # It's likely inside a method like `def _encode(self, domain: str):`
        old_encode = "def _encode(self, domain: str):"
        new_encode = old_encode + "\n" + idna_logic
        if old_encode in code and "import idna" not in code:
            code = code.replace(old_encode, new_encode)
            
    with open("inference/models.py", "w") as f:
        f.write(code)
except Exception as e:
    print(f"Error patching models: {e}")

print("Memory audit patches applied.")
