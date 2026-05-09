"""Tool-call record (v1, frozen)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ToolCallRecord(BaseModel):
    tool_name: str
    input_params: dict[str, Any]
    result_summary: str
    raw_result: dict[str, Any] = Field(default_factory=dict)
    source_available: bool = True
    latency_ms: int = 0
    called_at: datetime = Field(default_factory=datetime.utcnow)
    error: str | None = None
