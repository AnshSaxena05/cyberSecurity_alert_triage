"""Agent ReAct THINK structured output (v1, frozen)."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AgentThinkToolPlan(BaseModel):
    """One tool invocation planned by the ReAct THINK step."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Tool function name, e.g. query_splunk")
    arguments: str = Field(
        default="{}",
        max_length=4096,
        description='Tool arguments as a single JSON object string, e.g. {"query": "..."}',
    )

    @field_validator("arguments", mode="before")
    @classmethod
    def _coerce_arguments_json(cls, v: Any) -> str:
        if v is None:
            return "{}"
        if isinstance(v, dict):
            return json.dumps(v, separators=(",", ":"))
        if isinstance(v, str):
            return v
        return "{}"


class AgentThinkResponse(BaseModel):
    """Structured output from agent_think (ReAct THINK)."""

    model_config = ConfigDict(extra="forbid")

    tocontinue: bool = Field(
        ...,
        description="True if another round of planned_tools should run before verdict",
    )
    planned_tools: list[AgentThinkToolPlan] = Field(
        default_factory=list,
        max_length=8,
        description="Parallel tool calls when tocontinue is true; empty when false",
    )
    reasoning: str = Field(default="", max_length=2048, description="Brief analyst reasoning")
