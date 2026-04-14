"""
Tracer — OpenTelemetry span helpers for the SOC Triage pipeline.

Langfuse is now the primary observability backend (see observability/langfuse_client.py).
This module retains OpenTelemetry span helpers for infrastructure-level metrics and
the optional LangSmith integration for backward compatibility.

LangSmith tracing is enabled when LANGCHAIN_TRACING_V2=true and
LANGCHAIN_API_KEY is set in .env.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Generator

import structlog

logger = structlog.get_logger(__name__)


class NoOpSpan:
    """Null object pattern — used when tracing is disabled."""
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def set_attribute(self, key: str, value: Any) -> None: pass
    def add_event(self, name: str, attributes: dict | None = None) -> None: pass
    def record_exception(self, exc: Exception) -> None: pass


class SOCTracer:
    def __init__(self, enabled: bool = False, project: str = "soc-triage-agent") -> None:
        self._enabled = enabled
        self._project = project
        self._otel_tracer = None

        if enabled:
            self._setup_otel()

    def _setup_otel(self) -> None:
        try:
            from opentelemetry import trace
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter

            provider = TracerProvider()
            provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
            trace.set_tracer_provider(provider)
            self._otel_tracer = trace.get_tracer("soc-triage-agent")
            logger.info("otel_tracing_enabled")
        except Exception as exc:
            logger.warning("otel_setup_failed", error=str(exc))

    @contextmanager
    def trace_alert(
        self,
        alert_id: str,
        run_id: str | None = None,
    ) -> Generator[NoOpSpan, None, None]:
        if not self._enabled or not self._otel_tracer:
            yield NoOpSpan()
            return

        from opentelemetry import trace

        with self._otel_tracer.start_as_current_span(
            "soc.triage",
            attributes={
                "alert.id": alert_id,
                "run.id": run_id or "",
                "service.name": "soc-triage-agent",
            },
        ) as span:
            yield span

    @contextmanager
    def trace_node(self, node_name: str) -> Generator[NoOpSpan, None, None]:
        if not self._enabled or not self._otel_tracer:
            yield NoOpSpan()
            return

        from opentelemetry import trace

        with self._otel_tracer.start_as_current_span(
            f"soc.node.{node_name}",
        ) as span:
            start = time.time()
            try:
                yield span
            finally:
                elapsed = int((time.time() - start) * 1000)
                span.set_attribute("node.latency_ms", elapsed)

    def log_tool_call(
        self,
        tool_name: str,
        params: dict[str, Any],
        result_summary: str,
        latency_ms: int,
    ) -> None:
        logger.info(
            "tool_call_traced",
            tool=tool_name,
            latency_ms=latency_ms,
            result_summary=result_summary[:200],
        )


_tracer_instance: SOCTracer | None = None


def get_tracer() -> SOCTracer:
    global _tracer_instance
    if _tracer_instance is None:
        from app.config import get_settings
        s = get_settings()
        _tracer_instance = SOCTracer(
            enabled=s.langchain_tracing_v2,
            project=s.langchain_project,
        )
    return _tracer_instance


def flush_all() -> None:
    """Flush both OTel and Langfuse buffers at shutdown."""
    from observability.langfuse_client import langfuse_flush
    langfuse_flush()
