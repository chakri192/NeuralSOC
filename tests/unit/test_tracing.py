"""shared/tracing.py is opt-in: unset OTEL_EXPORTER_OTLP_ENDPOINT (the
default in every other test in this suite) means init_tracing() never
installs a real TracerProvider. These tests exercise both branches
directly, restoring the original global tracer provider afterward so
they can't leak state into any other test in the same process.
"""
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider

from shared.tracing import init_tracing


def test_tracing_disabled_by_default_returns_a_noop_tracer(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.setattr(trace, "_TRACER_PROVIDER", None)
    tracer = init_tracing("test-service")
    span = tracer.start_span("x")
    assert span.get_span_context().is_valid is False  # no-op provider produces a non-recording span
    trace._TRACER_PROVIDER = None


def test_tracing_enabled_installs_a_real_provider(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
    monkeypatch.setattr(trace, "_TRACER_PROVIDER", None)
    try:
        tracer = init_tracing("test-service")
        assert isinstance(trace.get_tracer_provider(), TracerProvider)
        span = tracer.start_span("x")
        assert span.get_span_context().is_valid is True  # a real TracerProvider produces a real span context
    finally:
        trace._TRACER_PROVIDER = None


def test_tracing_init_is_idempotent_within_one_process(monkeypatch):
    # A second call (e.g. a module reimport under pytest) must not attempt
    # to reconfigure an already-installed provider -- the OTel API only
    # allows setting it once per process and logs a warning otherwise.
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
    monkeypatch.setattr(trace, "_TRACER_PROVIDER", None)
    try:
        init_tracing("test-service")
        provider_after_first_call = trace.get_tracer_provider()
        init_tracing("test-service")  # must not raise or replace the provider
        assert trace.get_tracer_provider() is provider_after_first_call
    finally:
        trace._TRACER_PROVIDER = None
