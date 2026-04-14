"""
Backup Systems Tool — checks backup integrity and shadow copy status.

When BACKUP_API_URL is set, POSTs a JSON envelope to that HTTP endpoint.
Otherwise returns source_available=false with an explicit error.
"""

from __future__ import annotations

from typing import Any, Literal

import httpx
import structlog
from langchain_core.tools import tool
from langfuse import observe
from pydantic import BaseModel, Field

from app.config import get_settings

logger = structlog.get_logger(__name__)

_UNCONFIGURED_MSG = (
    "Backup vendor API URL not configured. Set BACKUP_API_URL (and optional BACKUP_API_TOKEN) in .env."
)


class BackupQueryInput(BaseModel):
    query_type: Literal[
        "shadow_copy_status",
        "backup_job_history",
        "recovery_point_availability",
    ] = Field(description="Type of backup system query")
    hostname: str | None = Field(None, description="Host to check VSS/shadow copies for")
    hours_back: int = Field(72, description="Look-back window in hours", ge=1, le=720)


@observe(name="query_backup_systems", as_type="span")
async def backup_query_async(params: BackupQueryInput) -> dict[str, Any]:
    settings = get_settings()
    url = (settings.backup_api_url or "").strip()
    if not url:
        logger.info("backup_tool_unconfigured", query_type=params.query_type)
        return {
            "source_available": False,
            "source": "backup_systems",
            "query_type": params.query_type,
            "hostname": params.hostname,
            "error": _UNCONFIGURED_MSG,
            "results": [],
        }

    body = {
        "query_type": params.query_type,
        "hostname": params.hostname,
        "hours_back": params.hours_back,
    }
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if settings.backup_api_token:
        headers["Authorization"] = f"Bearer {settings.backup_api_token}"

    try:
        async with httpx.AsyncClient(
            timeout=settings.tool_timeout_seconds,
            verify=True,
        ) as client:
            resp = await client.post(url, json=body, headers=headers)
            if resp.status_code >= 400:
                return {
                    "source_available": False,
                    "source": "backup_systems",
                    "error": f"Backup API HTTP {resp.status_code}: {resp.text[:300]}",
                    "results": [],
                }
            data = resp.json()
            if isinstance(data, dict):
                data.setdefault("source_available", True)
                data.setdefault("source", "backup_systems")
                return data
            return {
                "source_available": True,
                "source": "backup_systems",
                "query_type": params.query_type,
                "raw": data,
            }
    except httpx.TimeoutException:
        return {
            "source_available": False,
            "source": "backup_systems",
            "error": "Backup API timed out",
            "results": [],
        }
    except Exception as exc:
        logger.error("backup_api_error", error=str(exc))
        return {
            "source_available": False,
            "source": "backup_systems",
            "error": str(exc),
            "results": [],
        }


@tool("query_backup_systems", args_schema=BackupQueryInput)
async def query_backup_systems(
    query_type: str,
    hostname: str | None = None,
    hours_back: int = 72,
) -> dict[str, Any]:
    """
    Query backup and recovery systems for ransomware impact assessment. Use this tool to:
    - Check if Volume Shadow Copies (VSS) were deleted (query_type='shadow_copy_status')
    - Get backup job history to determine if recent backups are intact (query_type='backup_job_history')
    - Check available recovery points for affected hosts (query_type='recovery_point_availability')

    ALWAYS use for T1486 (Data Encrypted for Impact) and T1490 (Inhibit System Recovery).
    """
    params = BackupQueryInput(
        query_type=query_type,  # type: ignore[arg-type]
        hostname=hostname,
        hours_back=hours_back,
    )
    return await backup_query_async(params)
