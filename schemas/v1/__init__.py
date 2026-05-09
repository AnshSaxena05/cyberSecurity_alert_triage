"""
Frozen v1 schemas. Never edited after ship.

To make a breaking change: copy this directory to schemas/v2/, edit there, and
update producers/consumers per the cutover sequence in schemas/MIGRATIONS.md.
"""

from schemas._common import AlertSource, EscalationDecision, Severity
from schemas.v1.__version__ import SCHEMA_ID, SCHEMA_VERSION
from schemas.v1.agent_think import AgentThinkResponse, AgentThinkToolPlan
from schemas.v1.auto_ingest import AutoIngestFlatView
from schemas.v1.detection_finding import (
    AttackContext,
    DetectionFindingSlice,
    EvidenceBundle,
    FindingInfo,
    ObservableEntry,
)
from schemas.v1.extracted_entities import (
    ExtractedEntities,
    HostEntity,
    IOCEntity,
    ProcessEntity,
    TechniqueEntity,
    UserEntity,
)
from schemas.v1.normalized_alert import (
    NetworkActivity,
    NormalizedAlert,
    ProcessActivity,
    UserActivity,
)
from schemas.v1.tool_call import ToolCallRecord
from schemas.v1.triage_event import (
    PhaseEvent,
    TokenEvent,
    TriageCancelEvent,
    TriagePhase,
)
from schemas.v1.triage_verdict import ImmediateAction, MITREAssessment, TriageVerdict

__all__ = [
    "SCHEMA_VERSION",
    "SCHEMA_ID",
    # Enums (re-exported from _common for convenience)
    "AlertSource",
    "EscalationDecision",
    "Severity",
    # Detection finding slice
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
    # Triage events (NEW in v1, were not previously in app/models.py)
    "PhaseEvent",
    "TokenEvent",
    "TriageCancelEvent",
    "TriagePhase",
]
