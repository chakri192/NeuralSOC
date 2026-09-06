"""OpenTelemetry tracing setup shared by api/main.py, api/kafka_sink.py,
and inference/stream_processor_faust.py.

Tracing is opt-in: OTEL_EXPORTER_OTLP_ENDPOINT unset means init_tracing()
never installs an exporting TracerProvider, so every span is created
against the SDK's own no-op provider (near-zero overhead) -- the same
"always instrumented, nobody has to be scraping it" posture already used
for the Prometheus metrics elsewhere in this codebase.
"""
import os

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


def init_tracing(service_name: str):
    """Idempotent: the OTel API only allows one global TracerProvider per
    process, so a second call (e.g. a module reimport under pytest) must
    not attempt to reconfigure it -- it just returns a tracer bound to
    whatever provider (real or no-op) is already installed.
    """
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if endpoint and not isinstance(trace.get_tracer_provider(), TracerProvider):
        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint.rstrip('/')}/v1/traces"))
        )
        trace.set_tracer_provider(provider)
    return trace.get_tracer(service_name)
