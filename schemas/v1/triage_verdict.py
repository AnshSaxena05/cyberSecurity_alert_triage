"""Triage verdict — final structured output (v1, frozen)."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from schemas._common import EscalationDecision, Severity
from schemas.v1.extracted_entities import IOCEntity


class MITREAssessment(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float = Field(ge=0.0, le=1.0)


class ImmediateAction(BaseModel):
    priority: int = Field(ge=1, le=3)
    action: str
    target: str | None = None


class TriageVerdict(BaseModel):
    """
    Final structured output from the triage pipeline.
    Maps to the 6-section SOC analyst output format.
    """

    verdict_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_id: str
    tenant_id: str | None = None
    generated_at: datetime = Field(default_factory=datetime.utcnow)

    # Status — populated when triage was cancelled or terminated abnormally.
    # When unset (None), the verdict is the regular completed output.
    status: str | None = Field(
        default=None,
        description=(
            "None for normal completion; 'cancelled' when worker stopped "
            "due to a triage.cancel signal from the gateway"
        ),
    )

    # Section 1 — Severity Assessment
    severity: Severity
    severity_justification: str

    # Section 2 — Threat Classification
    mitre_assessments: list[MITREAssessment]

    # Section 3 — Triage Summary
    triage_summary: str = Field(
        description="3-5 sentences: what happened, attack chain, objective"
    )

    # Section 4 — IOCs
    confirmed_iocs: list[IOCEntity] = Field(default_factory=list)

    # Section 5 — Immediate Actions
    immediate_actions: list[ImmediateAction] = Field(default_factory=list)

    # Section 6 — Escalation
    escalation: EscalationDecision
    escalation_rationale: str

    # Pipeline metadata
    total_tool_calls: int = 0
    tools_called: list[str] = Field(default_factory=list)
    analyst_confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    false_positive_probability: float = Field(ge=0.0, le=1.0, default=0.1)
