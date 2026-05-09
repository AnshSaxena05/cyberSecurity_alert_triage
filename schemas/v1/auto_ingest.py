"""Auto-ingest LLM coercion structured output (v1, frozen)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AutoIngestFlatView(BaseModel):
    """
    Structured output when /ingest/auto uses the fast LLM to flatten unknown JSON
    into fields the generic normaliser understands. Values must be grounded in the input.
    """

    title: str = Field(..., max_length=512, description="Short alert title from payload facts")
    description: str = Field(
        default="",
        max_length=8000,
        description="What happened; no invented IOCs",
    )
    severity: str = Field(
        default="medium",
        description="One of: low, medium, high, critical (mapped like Splunk urgency)",
    )
    hostname: str | None = Field(None, max_length=256)
    mitre_technique: str | None = Field(None, max_length=32)
    mitre_tactic: str | None = Field(None, max_length=128)
    source_alert_id: str | None = Field(None, max_length=256)
