"""
CMDB Tool — queries the Configuration Management Database for asset context.

Provides: asset owner, criticality tier, business unit, patch status,
open vulnerabilities, and network zone. This is deterministic context
that enriches every alert regardless of technique.

When SERVICENOW_INSTANCE_URL is configured, queries the ServiceNow CMDB
Table API (cmdb_ci). Otherwise returns source_available=false with an explicit error.
"""

from __future__ import annotations

import base64
import time
from typing import Any, Literal

import httpx
import structlog
from langchain_core.tools import tool
from langfuse import observe
from pydantic import BaseModel, Field

from app.config import get_settings

logger = structlog.get_logger(__name__)

CRITICALITY_TIERS = {
    "crown_jewel": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "unknown": 1,
}

SERVICENOW_CRITICALITY_MAP = {
    "1": "crown_jewel",
    "2": "high",
    "3": "medium",
    "4": "low",
}


class CMDBInput(BaseModel):
    lookup_type: Literal["by_hostname", "by_ip", "by_owner"] = Field(
        description="How to look up the asset"
    )
    hostname: str | None = Field(None, description="Hostname to look up")
    ip_address: str | None = Field(None, description="IP address to look up")
    owner: str | None = Field(None, description="Asset owner (username or team name)")


# ---------------------------------------------------------------------------
# ServiceNow auth helpers
# ---------------------------------------------------------------------------

_snow_token_cache: dict[str, Any] = {}


async def _get_snow_auth_headers(client: httpx.AsyncClient) -> dict[str, str]:
    """Return auth headers for ServiceNow — OAuth2 if client_id is set, else Basic."""
    settings = get_settings()

    if settings.servicenow_client_id and settings.servicenow_client_secret:
        now = time.time()
        if _snow_token_cache.get("expires_at", 0) > now + 30:
            return {"Authorization": f"Bearer {_snow_token_cache['token']}"}

        resp = await client.post(
            f"{settings.servicenow_instance_url}/oauth_token.do",
            data={
                "grant_type": "password",
                "client_id": settings.servicenow_client_id,
                "client_secret": settings.servicenow_client_secret,
                "username": settings.servicenow_username,
                "password": settings.servicenow_password,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        token_data = resp.json()
        _snow_token_cache["token"] = token_data["access_token"]
        _snow_token_cache["expires_at"] = now + token_data.get("expires_in", 1800)
        return {"Authorization": f"Bearer {_snow_token_cache['token']}"}

    userpass = f"{settings.servicenow_username}:{settings.servicenow_password}"
    b64 = base64.b64encode(userpass.encode()).decode()
    return {"Authorization": f"Basic {b64}"}


# ---------------------------------------------------------------------------
# Real ServiceNow CMDB query
# ---------------------------------------------------------------------------

async def _query_servicenow_cmdb(params: CMDBInput) -> dict[str, Any] | None:
    """Query ServiceNow Table API for cmdb_ci records. Returns None on failure."""
    settings = get_settings()
    if not settings.servicenow_instance_url or not settings.servicenow_username:
        return None

    if params.lookup_type == "by_hostname":
        sysparm_query = f"name={params.hostname}"
    elif params.lookup_type == "by_ip":
        sysparm_query = f"ip_address={params.ip_address}"
    elif params.lookup_type == "by_owner":
        sysparm_query = f"owned_by.user_name={params.owner}"
    else:
        return None

    base = settings.servicenow_instance_url.rstrip("/")
    url = f"{base}/api/now/table/cmdb_ci"

    try:
        async with httpx.AsyncClient(
            timeout=settings.tool_timeout_seconds,
            verify=True,
        ) as client:
            auth_headers = await _get_snow_auth_headers(client)
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                **auth_headers,
            }
            resp = await client.get(
                url,
                headers=headers,
                params={
                    "sysparm_query": sysparm_query,
                    "sysparm_limit": 1,
                    "sysparm_display_value": "true",
                },
            )
            resp.raise_for_status()
            records = resp.json().get("result", [])
            if not records:
                return {
                    "source": "cmdb",
                    "found": False,
                    "hostname": params.hostname or params.ip_address or "unknown",
                }

            r = records[0]
            raw_criticality = str(r.get("busines_criticality", r.get("operational_status", "4")))
            criticality = SERVICENOW_CRITICALITY_MAP.get(raw_criticality, "unknown")

            return {
                "source": "cmdb",
                "found": True,
                "hostname": r.get("name", params.hostname),
                "asset_type": r.get("sys_class_name", "Unknown"),
                "criticality": criticality,
                "criticality_score": CRITICALITY_TIERS.get(criticality, 1),
                "business_unit": r.get("department", r.get("company", "Unknown")),
                "owner": r.get("owned_by", r.get("assigned_to", "unknown")),
                "os": r.get("os", "Unknown"),
                "patch_status": "up_to_date" if r.get("unverified") == "false" else "needs_review",
                "network_zone": r.get("dns_domain", "corporate"),
                "open_vulns_critical": 0,
                "last_seen": r.get("last_discovered", r.get("sys_updated_on", "")),
                "managed_by_edr": bool(r.get("discovery_source")),
                "sys_id": r.get("sys_id"),
            }

    except httpx.TimeoutException:
        logger.warning("servicenow_cmdb_timeout")
        return {"source_available": False, "error": "ServiceNow CMDB query timed out"}
    except Exception as exc:
        logger.error("servicenow_cmdb_error", error=str(exc))
        return None


# ---------------------------------------------------------------------------
# Async implementation
# ---------------------------------------------------------------------------

_CMDB_NOT_CONFIGURED = (
    "ServiceNow CMDB is not configured. Set SERVICENOW_INSTANCE_URL, "
    "SERVICENOW_USERNAME, and SERVICENOW_PASSWORD in .env "
    "(optional OAuth: SERVICENOW_CLIENT_ID and SERVICENOW_CLIENT_SECRET)."
)

_CMDB_QUERY_FAILED = (
    "ServiceNow CMDB request failed (HTTP error, timeout, or invalid credentials). "
    "Check instance URL, user ACLs on cmdb_ci, and logs."
)


@observe(name="query_cmdb", as_type="span")
async def cmdb_query_async(params: CMDBInput) -> dict[str, Any]:
    settings = get_settings()

    if not settings.servicenow_instance_url or not settings.servicenow_username:
        return {
            "source_available": False,
            "source": "cmdb",
            "error": _CMDB_NOT_CONFIGURED,
        }

    result = await _query_servicenow_cmdb(params)
    if result is not None:
        return result

    logger.warning("servicenow_cmdb_query_failed", lookup_type=params.lookup_type)
    return {
        "source_available": False,
        "source": "cmdb",
        "error": _CMDB_QUERY_FAILED,
    }


@tool("query_cmdb", args_schema=CMDBInput)
async def query_cmdb(
    lookup_type: str,
    hostname: str | None = None,
    ip_address: str | None = None,
    owner: str | None = None,
) -> dict[str, Any]:
    """
    Query the asset Configuration Management Database (CMDB) for context about
    a host or user.     Queries ServiceNow CMDB Table API when configured; otherwise returns an error.
    Use this tool to:
    - Determine the criticality of a host (crown_jewel / high / medium / low)
    - Find the business owner of an asset
    - Check if the host is managed by EDR
    - Understand the network zone (DMZ, corporate, cloud)
    - Get patch status and open critical vulnerabilities

    Always use this tool for T1021 (lateral movement) alerts to determine
    if the target host is a high-value asset (domain controller, backup server, database).
    Use early — asset criticality gates the severity escalation decision.
    """
    params = CMDBInput(
        lookup_type=lookup_type,  # type: ignore[arg-type]
        hostname=hostname,
        ip_address=ip_address,
        owner=owner,
    )
    return await cmdb_query_async(params)
