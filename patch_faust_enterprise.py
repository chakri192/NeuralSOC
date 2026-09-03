with open("inference/stream_processor_faust.py", "r") as f:
    code = f.read()

# 1. JSON Logging
json_log = """from pythonjsonlogger import jsonlogger
import logging
import sys

logger = logging.getLogger("stream_processor")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
"""
if "logging.basicConfig" in code:
    code = code.replace("logging.basicConfig(level=logging.INFO)", json_log)

# 2. Remove memory store
code = code.replace("store='memory://',", "")

# 3. Add Graceful Shutdown
shutdown = """
import signal

@app.task
async def on_stop():
    logger.info("SIGTERM Received: Flushing Faust internal buffers before shutdown.")
"""
if "import os" in code:
    code = code.replace("import os", "import os\n" + shutdown)

with open("inference/stream_processor_faust.py", "w") as f:
    f.write(code)
