import re

with open("inference/stream_processor_faust.py", "r") as f:
    code = f.read()

# Increase concurrency to 4
code = code.replace("@app.agent(raw_traffic_topic)", "@app.agent(raw_traffic_topic, concurrency=4)")

# Await enrichment
code = code.replace("enricher.enrich(alert)", "await enricher.enrich(alert)")

with open("inference/stream_processor_faust.py", "w") as f:
    f.write(code)
