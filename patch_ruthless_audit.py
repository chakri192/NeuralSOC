import re

# 1. Patch Enrichment MD5 -> SHA256
try:
    with open("inference/enrichment.py", "r") as f:
        code = f.read()
    code = code.replace("hashlib.md5", "hashlib.sha256").replace(", usedforsecurity=False", "")
    with open("inference/enrichment.py", "w") as f:
        f.write(code)
except Exception as e:
    print(f"Error patching enrichment: {e}")

# 2. Patch Correlation Redis LTRIM and Pool
try:
    with open("inference/correlation.py", "r") as f:
        code = f.read()
    
    # Add connection pool
    if "ConnectionPool" not in code:
        code = code.replace(
            "self.redis = redis.Redis(host=redis_host, port=6379, db=0, decode_responses=True)",
            "pool = redis.ConnectionPool(host=redis_host, port=6379, db=0, decode_responses=True)\n        self.redis = redis.Redis(connection_pool=pool)"
        )
    
    # Add LTRIM to cap list size
    if "self.redis.ltrim" not in code:
        code = code.replace(
            "self.redis.expire(key, self.time_window_sec)",
            "self.redis.ltrim(key, 0, 99)\n        self.redis.expire(key, self.time_window_sec)"
        )
    with open("inference/correlation.py", "w") as f:
        f.write(code)
except Exception as e:
    print(f"Error patching correlation: {e}")

# 3. Patch Faust processor (timeouts and path hack)
try:
    with open("inference/stream_processor_faust.py", "r") as f:
        code = f.read()
    
    # Remove sys.path.append
    code = re.sub(r'sys\.path\.append\(.*?\)\n', '', code)
    
    # Add wait_for timeouts to the threads
    old_ml = """            # 2. Run rule engine and ML model concurrently
            rule_task = asyncio.to_thread(evaluate_rules, event, features)
            ml_task   = asyncio.to_thread(app.orchestrator.evaluate, event, features)
            rule_res, ml_res = await asyncio.gather(rule_task, ml_task)"""
            
    new_ml = """            # 2. Run rule engine and ML model concurrently with timeouts to prevent stalling
            rule_task = asyncio.to_thread(evaluate_rules, event, features)
            ml_task   = asyncio.to_thread(app.orchestrator.evaluate, event, features)
            rule_res, ml_res = await asyncio.wait_for(asyncio.gather(rule_task, ml_task), timeout=5.0)"""
            
    code = code.replace(old_ml, new_ml)
    
    with open("inference/stream_processor_faust.py", "w") as f:
        f.write(code)
except Exception as e:
    print(f"Error patching faust: {e}")

print("Ruthless audit patches applied.")
