"""
Application configuration via Pydantic Settings.
All values can be overridden with environment variables or a .env file.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------ #
    # Application
    # ------------------------------------------------------------------ #
    app_name: str = "SOC Triage Agent"
    app_version: str = "0.1.0"
    debug: bool = False
    log_level: str = "INFO"
    environment: Literal["development", "staging", "production"] = "development"

    # ------------------------------------------------------------------ #
    # Ollama / Local LLM
    # ------------------------------------------------------------------ #
    ollama_base_url: str = "http://localhost:11434"
    # Deep reasoning model — Foundation-Sec-8B for domain-specific SOC triage
    deep_model: str = "axonvertex/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:Q8_0_24K"
    # Fast model — llama3.2:3b for entity extraction (deterministic, cheap)
    fast_model: str = "axonvertex/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:Q8_0_24K" #"llama3.2:3b"
    ollama_num_ctx: int = 8192
    ollama_keep_alive: str = "10m"   # keep model hot between requests
    ollama_timeout: int = 180       # seconds

    # ------------------------------------------------------------------ #
    # OpenAI fallback (used when local Ollama model is unavailable)
    # ------------------------------------------------------------------ #
    openai_api_key: str = ""
    openai_model: str = "gpt-4.1-mini"

    # ------------------------------------------------------------------ #
    # LangSmith Observability (kept for backward compatibility)
    # ------------------------------------------------------------------ #
    langchain_tracing_v2: bool = False
    langchain_api_key: str = ""
    langchain_project: str = "soc-triage-agent"

    # ------------------------------------------------------------------ #
    # Langfuse Observability
    # ------------------------------------------------------------------ #
    langfuse_enabled: bool = False
    langfuse_secret_key: str = ""
    langfuse_public_key: str = ""
    # Must match project region: EU https://cloud.langfuse.com | US https://us.cloud.langfuse.com
    langfuse_base_url: str = "https://cloud.langfuse.com"
    langfuse_project: str = "soc-triage-agent"
    langfuse_prompt_management: bool = False   # opt-in for remote prompt fetch

    # ------------------------------------------------------------------ #
    # Redis Cache
    # ------------------------------------------------------------------ #
    redis_url: str = "redis://localhost:6379/0"
    cache_ttl_seconds: int = 900    # 15-minute IOC cache window
    cache_enabled: bool = True

    # ------------------------------------------------------------------ #
    # Tool: Splunk
    # ------------------------------------------------------------------ #
    splunk_host: str = "localhost"
    splunk_port: int = 8089
    splunk_username: str = "admin"
    splunk_password: str = ""
    splunk_token: str = ""          # preferred over username/password
    splunk_scheme: str = "https"
    splunk_verify_ssl: bool = False

    # ------------------------------------------------------------------ #
    # Tool: CrowdStrike
    # ------------------------------------------------------------------ #
    crowdstrike_client_id: str = ""
    crowdstrike_client_secret: str = ""
    crowdstrike_base_url: str = "https://api.crowdstrike.com"

    # ------------------------------------------------------------------ #
    # Tool: AWS
    # ------------------------------------------------------------------ #
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_region: str = "us-east-1"

    # ------------------------------------------------------------------ #
    # Tool: ServiceNow ITSM / CMDB
    # ------------------------------------------------------------------ #
    servicenow_instance_url: str = ""    # e.g. https://yourinstance.service-now.com
    servicenow_username: str = ""
    servicenow_password: str = ""
    servicenow_client_id: str = ""       # OAuth2 (optional, Basic auth used when empty)
    servicenow_client_secret: str = ""   # OAuth2 (optional)

    # ------------------------------------------------------------------ #
    # Tool: Threat Intel
    # ------------------------------------------------------------------ #
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""           # AlienVault OTX

    # ------------------------------------------------------------------ #
    # Tool: VulnCheck (CVE enrichment)
    # ------------------------------------------------------------------ #
    vulncheck_api_token: str = ""

    # ------------------------------------------------------------------ #
    # Pipeline Behaviour
    # ------------------------------------------------------------------ #
    # Tool call budgets per severity (matches context doc Layer 5)
    budget_low: int = 3
    budget_medium: int = 5
    budget_high: int = 8
    budget_critical: int = 10

    # Per-source query timeout
    tool_timeout_seconds: int = 30

    # POST /ingest/auto: when source is ambiguous (generic), call fast LLM to map JSON → flat fields
    auto_ingest_coerce_llm: bool = True

    # Persist alerts/verdicts/jobs to Redis (same REDIS_URL as cache). When false, in-process memory only.
    verdict_persistence_enabled: bool = False

    # POST JSON to this URL when triage completes successfully (empty = disabled)
    triage_complete_webhook_url: str = ""

    # Optional NDR / flow HTTP API for query_netflow (POST JSON body; empty = tool returns unconfigured)
    ndr_flow_api_url: str = ""
    ndr_flow_api_token: str = ""

    # Optional backup vendor HTTP API (POST JSON; empty = unconfigured)
    backup_api_url: str = ""
    backup_api_token: str = ""

    # FastAPI webhook
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_key: str = Field(default="analyse_alert")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
