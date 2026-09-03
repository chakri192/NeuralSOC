import os
import re

# 1. inference/correlation.py: Add Lua script & max_connections
try:
    with open("inference/correlation.py", "r") as f:
        corr = f.read()
    
    corr = corr.replace(
        "pool = redis.ConnectionPool(host=redis_host, port=6379, db=0, decode_responses=True, socket_timeout=2.0, socket_connect_timeout=2.0)",
        "pool = redis.ConnectionPool(host=redis_host, port=6379, db=0, decode_responses=True, socket_timeout=2.0, socket_connect_timeout=2.0, max_connections=100)"
    )
    
    lua_script = """
        self._correlate_script = self.redis.register_script('''
            local key = KEYS[1]
            local window = tonumber(ARGV[1])
            local max_records = tonumber(ARGV[2])
            redis.call('LPUSH', key, ARGV[3])
            redis.call('LTRIM', key, 0, max_records - 1)
            redis.call('EXPIRE', key, window)
            local records = redis.call('LRANGE', key, 0, -1)
            return records
        ''')
"""
    if "self._correlate_script" not in corr:
        corr = corr.replace("self.time_window_sec = int(os.getenv(\"CORRELATION_WINDOW\", \"300\"))", "self.time_window_sec = int(os.getenv(\"CORRELATION_WINDOW\", \"300\"))\n" + lua_script)
    
    # Replace the read-modify-write race condition with the Lua script execution
    race_condition = """        # Store alert in Redis list with TTL
        key = f"alerts:{src_ip}"
        self.redis.lpush(key, json.dumps(alert))
        self.redis.ltrim(key, 0, 99)
        self.redis.expire(key, self.time_window_sec)

        # Retrieve and correlate
        records = self.redis.lrange(key, 0, -1)
        records = [json.loads(r) for r in records]"""
        
    safe_lua = """        key = f"alerts:{src_ip}"
        raw_records = self._correlate_script(keys=[key], args=[self.time_window_sec, 100, json.dumps(alert)])
        records = []
        for r in raw_records:
            try:
                records.append(json.loads(r))
            except Exception:
                pass # Drop corrupt JSON (Fix 5.4 DoS)"""
    
    if race_condition in corr:
        corr = corr.replace(race_condition, safe_lua)

    with open("inference/correlation.py", "w") as f:
        f.write(corr)
except Exception as e:
    print(f"Error corr: {e}")

# 2. inference/stream_processor_faust.py: Fix ThreadPool CPU starvation & PyTorch thread safety
try:
    with open("inference/stream_processor_faust.py", "r") as f:
        faust = f.read()
    
    faust = faust.replace("executor = ThreadPoolExecutor(max_workers=16)", 
                          "import torch\ntorch.set_num_threads(1)\nCPU_COUNT = max(1, os.cpu_count() or 1)\nexecutor = ThreadPoolExecutor(max_workers=CPU_COUNT)")
    
    faust = faust.replace("await app.stop()", 
                          "await app.stop()\n    try:\n        app.correlator.redis.connection_pool.disconnect()\n    except Exception:\n        pass")
                          
    with open("inference/stream_processor_faust.py", "w") as f:
        f.write(faust)
except Exception as e:
    print(f"Error faust: {e}")

# 3. api/main.py: Fix CORS and limit metrics
try:
    with open("api/main.py", "r") as f:
        api = f.read()
    
    api = api.replace('allow_methods=["*"]', 'allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]')
    api = api.replace('@app.get("/metrics")', '@app.get("/metrics")\n@limiter.limit("10/second")')
    
    with open("api/main.py", "w") as f:
        f.write(api)
except Exception as e:
    print(f"Error api: {e}")

# 4. api/database.py: Add pool_pre_ping
try:
    with open("api/database.py", "r") as f:
        db = f.read()
    
    db = db.replace('connect_args=connect_args', 'connect_args=connect_args, pool_pre_ping=True, pool_size=20, max_overflow=20')
    
    with open("api/database.py", "w") as f:
        f.write(db)
except Exception as e:
    print(f"Error db: {e}")

# 5. api/kafka_sink.py: Fix bulk insert bug with empty alert_id
try:
    with open("api/kafka_sink.py", "r") as f:
        sink = f.read()
    
    buggy_append = 'batch.append(Alert(**data))'
    safe_append = 'if not data.get("alert_id"):\n                    continue\n                batch.append(Alert(**data))'
    
    sink = sink.replace(buggy_append, safe_append)
    with open("api/kafka_sink.py", "w") as f:
        f.write(sink)
except Exception as e:
    print(f"Error sink: {e}")

# 6. inference/rules.py: Fix TypeError and False Positives
try:
    with open("inference/rules.py", "r") as f:
        rules = f.read()
    
    rules = rules.replace('event.get("orig_pkts", 0) > 10000', 'int(event.get("orig_pkts", 0)) > 10000')
    rules = rules.replace('entropy > 3.8 and length >= 10', 'entropy > 3.8 and length >= 10 and digit_ratio > 0.3')
    
    with open("inference/rules.py", "w") as f:
        f.write(rules)
except Exception as e:
    print(f"Error rules: {e}")

# 7. Add Faust to requirements.txt
try:
    with open("requirements.txt", "a") as f:
        f.write("\nfaust\n")
except Exception as e:
    pass

print("Chinese audit patches applied.")
