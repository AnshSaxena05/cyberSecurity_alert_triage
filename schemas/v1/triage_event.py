"""
Triage event envelopes for the NATS event stream (v1).

Phase events fire on coarse state transitions (~7 per triage). Token events
fire per LLM token under interest-gating; consumers verify ordering with
``event_seq`` and dedup on ``(alert_id, event_seq)``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

TriagePhase = Literal[
    "queued",
    "extract",
    "route",
    "burst",
    "react",
    "execute_tool",
    "verdict",
    "done",
    "failed",
    "cancelled",
]


class _EventBase(BaseModel):
    """Common envelope for every NATS-published triage event."""

    alert_id: str
    tenant_id: str
    event_seq: int = Field(
        ...,
        description=(
            "Monotonic per alert_id from Redis INCR seq:{alert_id}; "
            "consumers use as the NATS subscribe start sequence"
        ),
    )
    emitted_at: datetime = Field(default_factory=datetime.utcnow)
    trace_id: str | None = None


class PhaseEvent(_EventBase):
    """Coarse phase transition. Always published, ack-aware."""

    kind: Literal["phase"] = "phase"
    phase: TriagePhase
    detail: dict[str, Any] | None = Field(
        default=None,
        description="Optional small payload, e.g. tool name on execute_tool",
    )


class TokenEvent(_EventBase):
    """Single LLM token. Published only when interest:{alert_id} is set."""

    kind: Literal["token"] = "token"
    node: str = Field(..., description="LangGraph node that produced the token, e.g. agent_think")
    text: str = Field(..., description="The streamed token chunk")


class TriageCancelEvent(BaseModel):
    """
    Published by the gateway/DO to triage.cancel.v1.{tenant}.{alert} when a
    browser closes without a verdict. Worker checks cancelled:{alert_id} at
    each LLM-call boundary; a 5-second debounce prevents false cancels on
    quick tab-reopen.
    """

    alert_id: str
    tenant_id: str
    user_id: str | None = None
    reason: Literal["ws_closed", "user_request", "admin"] = "ws_closed"
    requested_at: datetime = Field(default_factory=datetime.utcnow)
