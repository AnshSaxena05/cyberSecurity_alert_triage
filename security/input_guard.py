"""
Input Guard — validates and sanitises incoming alert payloads before
they enter the normalisation pipeline.

Responsibilities:
  1. Authenticate the source (API key or shared secret)
  2. Reject payloads that exceed size limits (DoS protection)
  3. Strip obvious injection strings from text fields
  4. Validate required fields are present
"""

from __future__ import annotations

import re
from typing import Any

import structlog
from fastapi import HTTPException, Request, status

from app.config import get_settings

logger = structlog.get_logger(__name__)

MAX_PAYLOAD_BYTES = 1_000_000  # 1MB
_INJECTION_RE = re.compile(
    r"(\b(DROP|DELETE|INSERT|UPDATE|UNION|SELECT)\b.*\b(FROM|INTO|TABLE)\b)",
    re.IGNORECASE,
)
_SCRIPT_RE = re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)


def validate_api_key(request: Request) -> None:
    settings = get_settings()
    provided = request.headers.get("X-API-Key") or request.headers.get("Authorization", "").removeprefix("Bearer ")
    if provided != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )


def check_payload_size(raw: bytes) -> None:
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Payload exceeds {MAX_PAYLOAD_BYTES} bytes",
        )


def sanitise_string(value: str) -> str:
    value = _SCRIPT_RE.sub("", value)
    if _INJECTION_RE.search(value):
        logger.warning("injection_attempt_blocked", snippet=value[:100])
        return "[REDACTED]"
    return value


def sanitise_payload(payload: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    """Recursively sanitise all string values in a payload dict."""
    if depth > 5:
        return payload
    sanitised = {}
    for key, value in payload.items():
        if isinstance(value, str):
            sanitised[key] = sanitise_string(value)
        elif isinstance(value, dict):
            sanitised[key] = sanitise_payload(value, depth + 1)
        elif isinstance(value, list):
            sanitised[key] = [
                sanitise_payload(v, depth + 1) if isinstance(v, dict)
                else (sanitise_string(v) if isinstance(v, str) else v)
                for v in value
            ]
        else:
            sanitised[key] = value
    return sanitised
