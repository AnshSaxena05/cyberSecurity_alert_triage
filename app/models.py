"""
Core Pydantic models for the SOC Triage Agent.

Covers three tiers:
  1. Ingestion — raw alert sources normalised to OCSF
  2. Analysis — entities extracted from the alert
  3. Output   — structured triage verdict
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertSource(str, Enum):
    SPLUNK = "splunk"
    CROWDSTRIKE = "crowdstrike"
    AWS_GUARDDUTY = "aws_guardduty"
    SENTINEL = "sentinel"
    GENERIC = "generic"


class EscalationDecision(str, Enum):
    ESCALATE_IR = "ESCALATE_IR"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    MONITOR = "MONITOR"
    CLOSE = "CLOSE"


# ---------------------------------------------------------------------------
# OCSF-aligned Normalised Alert
# ---------------------------------------------------------------------------


class NetworkActivity(BaseModel):
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None


class ProcessActivity(BaseModel):
    process_name: str | None = None
    process_path: str | None = None
    process_id: int | None = None
    parent_process_name: str | None = None
    command_line: str | None = None
    hash_md5: str | None = None
    hash_sha256: str | None = None


class UserActivity(BaseModel):
    username: str | None = None
    domain: str | None = None
    uid: str | None = None
    is_privileged: bool = False
    auth_protocol: str | None = None


# OCSF Findings (Category UID 2) — DetectionFinding (Class UID 2004) LLM slice
# ---------------------------------------------------------------------------


class FindingInfo(BaseModel):
    """OCSF `finding_info`-aligned core alert metadata (bounded for LLM context)."""

    title: str = ""
    desc: str = ""
    product_uid: str | None = Field(None, description="Source product identifier, e.g. splunk, crowdstrike")
    severity_id: int | None = Field(
        None,
        description="OCSF-style 1–6 severity when mapped from vendor; optional",
        ge=1,
        le=6,
    )


class ObservableEntry(BaseModel):
    """Single surfaced entity / IOC for routing and LLM consumption."""

    type: str = Field(..., description='e.g. "IPv4 Address", "User", "Hostname", "SHA-256 Hash"')
    value: str = Field(..., max_length=2048)


class AttackContext(BaseModel):
    """MITRE ATT&CK context in one place."""

    tactic_name: str | None = None
    technique_uid: str | None = Field(None, description="e.g. T1059.001")


class EvidenceBundle(BaseModel):
    """Summarized proof snippet — strictly bounded."""

    query_result: str | None = Field(None, max_length=8192)


class DetectionFindingSlice(BaseModel):
    """
    Thin projection of OCSF DetectionFinding (2004) — not the full nested schema.
    Populated by vendor parsers + detection_finding_builder for multi-SIEM/EDR/CDR ingress.
    """

    schema_version: str = "1.0.0"
    finding_info: FindingInfo
    observables: list[ObservableEntry] = Field(default_factory=list)
    attacks: AttackContext | None = None
    evidences: EvidenceBundle | None = None


class AutoIngestFlatView(BaseModel):
    """
    Structured output when /ingest/auto uses the fast LLM to flatten unknown JSON
    into fields the generic normaliser understands. Values must be grounded in the input.
    """

    title: str = Field(..., max_length=512, description="Short alert title from payload facts")
    description: str = Field(default="", max_length=8000, description="What happened; no invented IOCs")
    severity: str = Field(
        default="medium",
        description="One of: low, medium, high, critical (mapped like Splunk urgency)",
    )
    hostname: str | None = Field(None, max_length=256)
    mitre_technique: str | None = Field(None, max_length=32)
    mitre_tactic: str | None = Field(None, max_length=128)
    source_alert_id: str | None = Field(None, max_length=256)


class AgentThinkToolPlan(BaseModel):
    """One tool invocation planned by the ReAct THINK step."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Tool function name, e.g. query_splunk")
    # Stringified JSON object — not dict[str, Any]: OpenAI response_format requires
    # object schemas to set additionalProperties: false, which arbitrary dicts cannot satisfy.
    # Keep max_length modest: Ollama json_schema compiles a GBNF grammar; very large
    # string bounds (e.g. 16384) become char{0,N} and can exceed server grammar limits.
    arguments: str = Field(
        default="{}",
        max_length=4096,
        description='Tool arguments as a single JSON object string, e.g. {"query": "..."}',
    )

    @field_validator("arguments", mode="before")
    @classmethod
    def _coerce_arguments_json(cls, v: Any) -> str:
        """Allow dict-shaped values from non-OpenAI providers; API schema stays a string."""
        if v is None:
            return "{}"
        if isinstance(v, dict):
            return json.dumps(v, separators=(",", ":"))
        if isinstance(v, str):
            return v
        return "{}"


class AgentThinkResponse(BaseModel):
    """
    Structured output from agent_think (ReAct THINK).
    Routing uses `tocontinue` together with `tool_budget` and non-empty planned tools.
    """

    model_config = ConfigDict(extra="forbid")

    tocontinue: bool = Field(
        ...,
        description="True if another round of planned_tools should run before verdict; False when current enrichment is sufficient",
    )
    planned_tools: list[AgentThinkToolPlan] = Field(
        default_factory=list,
        max_length=8,
        description="Parallel tool calls when tocontinue is true; must be empty when tocontinue is false",
    )
    reasoning: str = Field(default="", max_length=2048, description="Brief analyst reasoning")


class NormalizedAlert(BaseModel):
    """
    OCSF-aligned representation of an ingested security alert.
    All raw source formats (Splunk, CrowdStrike, GuardDuty) are flattened here
    before entering the triage pipeline.
    """

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: AlertSource
    source_alert_id: str | None = None
    title: str
    description: str
    severity: Severity
    timestamp: datetime
    ingested_at: datetime = Field(default_factory=datetime.utcnow)

    # OCSF classification
    category_uid: int | None = None        # e.g. 1 = System Activity
    class_uid: int | None = None           # e.g. 1001 = File Activity
    activity_id: int | None = None

    # Context
    hostname: str | None = None
    asset_id: str | None = None
    cloud_region: str | None = None
    cloud_account_id: str | None = None

    # Nested activity
    network: NetworkActivity | None = None
    process: ProcessActivity | None = None
    user: UserActivity | None = None

    # Detected technique hints from the source (may be incomplete)
    mitre_tactic: str | None = None
    mitre_technique: str | None = None

    # OCSF Findings / DetectionFinding (2004) thin slice for LLM-safe multi-vendor envelope
    detection_finding: DetectionFindingSlice | None = None

    # Raw payload preserved for audit
    raw_payload: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Entity Extraction (Pydantic-enforced LLM output)
# ---------------------------------------------------------------------------


class HostEntity(BaseModel):
    hostname: str
    ip_addresses: list[str] = Field(default_factory=list)
    os_type: str | None = None
    is_server: bool | None = None
    asset_criticality: Literal["crown_jewel", "high", "medium", "low", "unknown"] = "unknown"


class UserEntity(BaseModel):
    username: str
    domain: str | None = None
    is_admin: bool = False
    is_service_account: bool = False


class ProcessEntity(BaseModel):
    name: str
    path: str | None = None
    command_line: str | None = None
    hash_sha256: str | None = None
    is_suspicious: bool = False
    suspicion_reason: str | None = None


class TechniqueEntity(BaseModel):
    technique_id: str           # e.g. "T1003.001"
    technique_name: str | None = None
    tactic: str | None = None   # e.g. "Credential Access"
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)


class IOCEntity(BaseModel):
    type: Literal["ip", "domain", "hash_md5", "hash_sha256", "url", "email", "filename"]
    value: str
    context: str | None = None


class ExtractedEntities(BaseModel):
    """
    Structured entity extraction result from the alert.
    This is produced by LLM.with_structured_output(ExtractedEntities)
    so every field is Pydantic-validated before entering the routing layer.
    """

    hosts: list[HostEntity] = Field(default_factory=list)
    users: list[UserEntity] = Field(default_factory=list)
    processes: list[ProcessEntity] = Field(default_factory=list)
    techniques: list[TechniqueEntity] = Field(default_factory=list)
    iocs: list[IOCEntity] = Field(default_factory=list)
    attack_chain_summary: str = Field(
        description="1-2 sentence description of what is happening in this alert"
    )


# ---------------------------------------------------------------------------
# Tool Call Record
# ---------------------------------------------------------------------------


class ToolCallRecord(BaseModel):
    tool_name: str
    input_params: dict[str, Any]
    result_summary: str
    raw_result: dict[str, Any] = Field(default_factory=dict)
    source_available: bool = True
    latency_ms: int = 0
    called_at: datetime = Field(default_factory=datetime.utcnow)
    error: str | None = None


# ---------------------------------------------------------------------------
# Triage Verdict (final structured output)
# ---------------------------------------------------------------------------


class MITREAssessment(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float = Field(ge=0.0, le=1.0)


class ImmediateAction(BaseModel):
    priority: int = Field(ge=1, le=3)
    action: str
    target: str | None = None   # e.g. "host: dc01", "user: jsmith"


class TriageVerdict(BaseModel):
    """
    Final structured output from the triage pipeline.
    Maps directly to the 6-section SOC analyst output format from the context doc.
    """

    verdict_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_id: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)

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
