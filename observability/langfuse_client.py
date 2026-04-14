"""
Langfuse observability client — centralised initialisation for the SOC Triage Agent.

Three-layer integration:
  1. @observe decorators on pipeline functions create the trace hierarchy
  2. CallbackHandler injected into every ChatOllama ainvoke() captures LLM generations
  3. Langfuse prompt management with local fallback via PromptRegistry

When LANGFUSE_ENABLED=false (default), every call is a no-op and zero network
requests are made to Langfuse.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Optional

import structlog

if TYPE_CHECKING:
    from langfuse._client.client import Langfuse
    from langfuse.langchain import CallbackHandler

logger = structlog.get_logger(__name__)

_client: Optional["Langfuse"] = None
_enabled: bool = False


def connect_langfuse(
    *,
    secret_key: str = "",
    public_key: str = "",
    host: str = "https://cloud.langfuse.com",
    enabled: bool = False,
) -> None:
    """
    Initialise the Langfuse singleton client at application startup.

    Called from app/main.py startup_event(). Safe to call multiple times —
    subsequent calls are no-ops if the client is already initialised.
    """
    global _client, _enabled

    if not enabled:
        logger.info("langfuse_disabled")
        return

    if _client is not None:
        return  # already initialised

    try:
        from langfuse import Langfuse

        resolved_base = (
            (host or "").strip()
            or os.getenv("LANGFUSE_BASE_URL", "").strip()
            or os.getenv("LANGFUSE_HOST", "").strip()
            or "https://cloud.langfuse.com"
        )
        _client = Langfuse(
            public_key=public_key or os.getenv("LANGFUSE_PUBLIC_KEY", ""),
            secret_key=secret_key or os.getenv("LANGFUSE_SECRET_KEY", ""),
            base_url=resolved_base,
        )
        _enabled = True
        logger.info("langfuse_connected", base_url=resolved_base)
        # EU default vs US cloud — keys and traces are region-specific.
        if resolved_base.rstrip("/") == "https://cloud.langfuse.com":
            logger.info(
                "langfuse_region_hint",
                hint=(
                    "Using default EU API host. If your project URL is us.cloud.langfuse.com, "
                    "set LANGFUSE_BASE_URL=https://us.cloud.langfuse.com in .env or traces will "
                    "not appear in the US project (and OTLP may return 401)."
                ),
            )
    except Exception as exc:
        logger.warning("langfuse_connect_failed", error=str(exc))
        _client = None
        _enabled = False


def is_enabled() -> bool:
    """Return True when Langfuse is initialised and tracing is active."""
    return _enabled and _client is not None


def get_langfuse() -> Optional["Langfuse"]:
    """Return the singleton Langfuse client, or None if disabled."""
    return _client if is_enabled() else None


def get_langfuse_handler() -> Optional["CallbackHandler"]:
    """
    Return a fresh CallbackHandler that inherits the active @observe trace context.

    MUST be called INSIDE a function decorated with @observe so that the
    LangChain callback context is correctly nested under the parent span.

    Returns None when Langfuse is disabled; callers use the pattern:
        handler = get_langfuse_handler()
        callbacks = [handler] if handler else []
        await llm.ainvoke(..., config={"callbacks": callbacks})
    """
    if not is_enabled():
        return None
    try:
        from langfuse.langchain import CallbackHandler
        return CallbackHandler()
    except Exception as exc:
        logger.warning("langfuse_handler_failed", error=str(exc))
        return None


def langfuse_flush() -> None:
    """Flush all buffered traces before process shutdown."""
    if _client is not None:
        try:
            _client.flush()
            logger.info("langfuse_flushed")
        except Exception as exc:
            logger.warning("langfuse_flush_failed", error=str(exc))


def prompt_management_enabled() -> bool:
    """Return True when remote Langfuse prompt management is opted in."""
    from app.config import get_settings
    try:
        return is_enabled() and get_settings().langfuse_prompt_management
    except Exception:
        return False
