"""OCSF-aligned normalized alert (v1, frozen)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from schemas._common import AlertSource, Severity
from schemas.v1.detection_finding import DetectionFindingSlice


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


class NormalizedAlert(BaseModel):
    """OCSF-aligned representation of an ingested security alert."""

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: AlertSource
    source_alert_id: str | None = None
    title: str
    description: str
    severity: Severity
    timestamp: datetime
    ingested_at: datetime = Field(default_factory=datetime.utcnow)

    # Multi-tenant context. Authoritative value comes from the verified service
    # JWT, never from the message body. See services/_runtime/tenant.py.
    tenant_id: str | None = None

    # OCSF classification
    category_uid: int | None = None
    class_uid: int | None = None
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

    # OCSF Findings / DetectionFinding (2004) thin slice
    detection_finding: DetectionFindingSlice | None = None

    # Raw payload preserved for audit
    raw_payload: dict[str, Any] = Field(default_factory=dict)

    # Audit-trail flags. Set when the auto-ingest path used the LLM coercion fallback.
    coerced_by_llm: bool = False
    coercion_trace_id: str | None = None
