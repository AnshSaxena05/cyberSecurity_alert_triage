"""
Re-export shim for the canonical Pydantic models.

The authoritative definitions live in `schemas/v1/`. Existing call sites
continue to import from `app.models` while the codebase migrates.

For new code, prefer:

    from schemas.v1 import NormalizedAlert, TriageVerdict
"""

from __future__ import annotations

from schemas._common import AlertSource, EscalationDecision, Severity
from schemas.v1 import (
    AgentThinkResponse,
    AgentThinkToolPlan,
    AttackContext,
    AutoIngestFlatView,
    DetectionFindingSlice,
    EvidenceBundle,
    ExtractedEntities,
    FindingInfo,
    HostEntity,
    IOCEntity,
    ImmediateAction,
    MITREAssessment,
    NetworkActivity,
    NormalizedAlert,
    ObservableEntry,
    PhaseEvent,
    ProcessActivity,
    ProcessEntity,
    TechniqueEntity,
    TokenEvent,
    ToolCallRecord,
    TriageCancelEvent,
    TriagePhase,
    TriageVerdict,
    UserActivity,
    UserEntity,
)

__all__ = [
    # Enums
    "AlertSource",
    "EscalationDecision",
    "Severity",
    # Detection finding
    "AttackContext",
    "DetectionFindingSlice",
    "EvidenceBundle",
    "FindingInfo",
    "ObservableEntry",
    # Normalized alert
    "NetworkActivity",
    "NormalizedAlert",
    "ProcessActivity",
    "UserActivity",
    # Entity extraction
    "ExtractedEntities",
    "HostEntity",
    "IOCEntity",
    "ProcessEntity",
    "TechniqueEntity",
    "UserEntity",
    # Agent think
    "AgentThinkResponse",
    "AgentThinkToolPlan",
    # Auto ingest
    "AutoIngestFlatView",
    # Tool call
    "ToolCallRecord",
    # Verdict
    "ImmediateAction",
    "MITREAssessment",
    "TriageVerdict",
    # Triage events
    "PhaseEvent",
    "TokenEvent",
    "TriageCancelEvent",
    "TriagePhase",
]
