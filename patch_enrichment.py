import re

with open("inference/enrichment.py", "r") as f:
    code = f.read()

# Add asyncio import if not exists
if "import asyncio" not in code:
    code = "import asyncio\n" + code

# Change def enrich to async def enrich
code = code.replace("def enrich(self, alert: dict) -> dict:", "async def enrich(self, alert: dict) -> dict:\n        # Simulate an asynchronous external API call\n        await asyncio.sleep(0.005)")

with open("inference/enrichment.py", "w") as f:
    f.write(code)
