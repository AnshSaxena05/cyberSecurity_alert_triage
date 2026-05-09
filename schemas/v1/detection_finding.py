"""OCSF DetectionFinding (2004) thin slice for multi-vendor envelope (v1)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class FindingInfo(BaseModel):
    """OCSF `finding_info`-aligned core alert metadata (bounded for LLM context)."""

    title: str = ""
    desc: str = ""
    product_uid: str | None = Field(None, description="Source product, e.g. splunk, crowdstrike")
    severity_id: int | None = Field(None, ge=1, le=6)


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
    """Thin projection of OCSF DetectionFinding (2004) — not the full nested schema."""

    schema_version: str = "1.0.0"
    finding_info: FindingInfo
    observables: list[ObservableEntry] = Field(default_factory=list)
    attacks: AttackContext | None = None
    evidences: EvidenceBundle | None = None
