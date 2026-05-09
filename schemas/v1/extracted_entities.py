"""Entity extraction structured output (v1, frozen)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


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
    technique_id: str
    technique_name: str | None = None
    tactic: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)


class IOCEntity(BaseModel):
    type: Literal["ip", "domain", "hash_md5", "hash_sha256", "url", "email", "filename"]
    value: str
    context: str | None = None


class ExtractedEntities(BaseModel):
    """Structured entity extraction result from the alert."""

    hosts: list[HostEntity] = Field(default_factory=list)
    users: list[UserEntity] = Field(default_factory=list)
    processes: list[ProcessEntity] = Field(default_factory=list)
    techniques: list[TechniqueEntity] = Field(default_factory=list)
    iocs: list[IOCEntity] = Field(default_factory=list)
    attack_chain_summary: str = Field(
        description="1-2 sentence description of what is happening in this alert"
    )
