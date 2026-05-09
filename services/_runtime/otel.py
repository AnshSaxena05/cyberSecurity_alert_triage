"""
OpenTelemetry initialisation for SOC triage processes.

What lives here:

  * ``init_otel()``: configures the global tracer + meter providers and
    wires OTLP exporters at the configured endpoint. Idempotent.
  * ``get_tracer(name)``: returns a tracer for the caller's module.
  * ``inject_trace_id_into_headers(headers)`` and ``extract_trace_id``:
    propagate the active trace across NATS message headers so a single
    triage shows up as one trace from ingest → broker → worker.

Why ClickHouse?

OTLP traces written to a local OTel collector (or directly to ClickHouse
via the ClickHouse OTLP receiver) give us SQL-queryable distributed
traces with very fast aggregation. For dev, running a `signoz` or
`openobserve` container alongside ClickHouse gives a working dashboard.

Activation rule:

  * ``OTEL_DISABLED=1``                 → no-op (dev default)
  * ``OTEL_EXPORTER_OTLP_ENDPOINT=...``  → init exporter
  * default                              → init exporter pointed at
    ``http://localhost:4317`` (the standard OTLP gRPC port)

If the exporter target is unreachable on boot, init logs a warning and
falls back to a no-op tracer so application code never crashes for an
observability outage.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager

import structlog

logger = structlog.get_logger(__name__)

_initialised = False


def init_otel(*, service_name: str | None = None) -> None:
    """Configure the OpenTelemetry SDK. Idempotent. Safe to call from any process."""
    global _initialised
    if _initialised:
        return

    if os.environ.get("OTEL_DISABLED") == "1":
        logger.info("otel_disabled_by_env")
        _initialised = True
        return

    endpoint = (
        os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        or "http://localhost:4317"
    )
    service = (
        service_name
        or os.environ.get("OTEL_SERVICE_NAME")
        or "soc-triage"
    )

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create(
            {
                "service.name": service,
                "service.version": "0.1.0",
            }
        )
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=endpoint, insecure=endpoint.startswith("http://"))
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _initialised = True
        logger.info("otel_initialised", endpoint=endpoint, service=service)
    except Exception as exc:
        logger.warning("otel_init_failed_falling_back_to_noop", error=str(exc))
        _initialised = True   # avoid repeated retries in the hot path


def get_tracer(name: str) -> object:
    """Return a tracer for ``name``. Creates a no-op tracer if init failed."""
    try:
        from opentelemetry import trace

        return trace.get_tracer(name)
    except Exception:
        return _NoOpTracer()


# ---------------------------------------------------------------------------
# NATS header trace propagation
# ---------------------------------------------------------------------------


_TRACEPARENT = "traceparent"
_TRACESTATE = "tracestate"


def inject_trace_id_into_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """
    Copy the active span's trace context into a header dict suitable for
    a NATS publish. Returns the modified dict (caller's view).
    """
    h = dict(headers or {})
    try:
        from opentelemetry import trace
        from opentelemetry.propagate import inject

        if trace.get_current_span().get_span_context().is_valid:
            inject(h)
    except Exception as exc:
        logger.warning("otel_header_inject_failed", error=str(exc))
    return h


def extract_trace_context(headers: dict[str, str] | None) -> object | None:
    """
    Extract a trace context from inbound headers (NATS message headers
    or HTTP). Returns the OTel context object suitable for use as the
    parent of a new span; ``None`` if extraction is unavailable.
    """
    if not headers:
        return None
    try:
        from opentelemetry.propagate import extract

        return extract(headers)
    except Exception as exc:
        logger.warning("otel_header_extract_failed", error=str(exc))
        return None


@contextmanager
def span(name: str, *, attributes: dict[str, object] | None = None) -> Iterator[object]:
    """Convenience context manager for one span. Falls back to no-op."""
    try:
        from opentelemetry import trace

        tracer = trace.get_tracer("soc-triage")
        with tracer.start_as_current_span(name, attributes=attributes or {}) as sp:
            yield sp
    except Exception:
        yield _NoOpSpan()


# ---------------------------------------------------------------------------
# No-op fallbacks
# ---------------------------------------------------------------------------


class _NoOpSpan:
    def set_attribute(self, *args, **kwargs) -> None: ...
    def set_status(self, *args, **kwargs) -> None: ...
    def record_exception(self, *args, **kwargs) -> None: ...
    def end(self) -> None: ...
    def __enter__(self): return self
    def __exit__(self, *args) -> None: return None


class _NoOpTracer:
    def start_as_current_span(self, *args, **kwargs):
        return _NoOpSpan()

    def start_span(self, *args, **kwargs):
        return _NoOpSpan()
