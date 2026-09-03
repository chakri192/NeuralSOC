with open("inference/stream_processor_faust.py", "r") as f:
    code = f.read()

redactor = """
            # Redact PII before sending to DLQ
            safe_event = dict(event)
            safe_event.pop("id.orig_h", None)
            safe_event.pop("id.resp_h", None)
            await dlq_topic.send(value={"raw_event": safe_event, "error": str(e), "timestamp": datetime.now(timezone.utc).isoformat()})
"""

old_dlq = 'await dlq_topic.send(value={"raw_event": event, "error": str(e), "timestamp": datetime.now(timezone.utc).isoformat()})'

if old_dlq in code:
    code = code.replace(old_dlq, redactor)

with open("inference/stream_processor_faust.py", "w") as f:
    f.write(code)
