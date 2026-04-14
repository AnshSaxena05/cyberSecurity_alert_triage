"""
CrowdStrike Tool — queries CrowdStrike Falcon API for endpoint detections,
process trees, and device context.

Uses OAuth2 client credentials flow for authentication.
Token is cached for its lifetime (~30 minutes) to avoid re-auth overhead.
"""

from __future__ import annotations

import time
from typing import Any, Literal

import httpx
import structlog
from langchain_core.tools import tool
from langfuse import observe
from pydantic import BaseModel, Field

from app.config import get_settings
from services.query_builder import CrowdStrikeQueryBuilder

logger = structlog.get_logger(__name__)

_token_cache: dict[str, Any] = {}


async def _get_token(client: httpx.AsyncClient) -> str:
    now = time.time()
    if _token_cache.get("expires_at", 0) > now + 30:
        return _token_cache["token"]
    settings = get_settings()
    resp = await client.post(
        f"{settings.crowdstrike_base_url}/oauth2/token",
        data={
            "client_id": settings.crowdstrike_client_id,
            "client_secret": settings.crowdstrike_client_secret,
        },
    )
    resp.raise_for_status()
    data = resp.json()
    _token_cache["token"] = data["access_token"]
    _token_cache["expires_at"] = now + data.get("expires_in", 1800)
    return _token_cache["token"]


# ---------------------------------------------------------------------------
# Input schema
# ---------------------------------------------------------------------------

class CrowdStrikeInput(BaseModel):
    query_type: Literal[
        "detections_by_host",
        "process_tree",
        "device_info",
        "ioc_lookup",
        "alerts_by_host",
        "incidents_by_host",
    ] = Field(description="Type of CrowdStrike query to perform")
    hostname: str | None = Field(None, description="Target hostname")
    device_id: str | None = Field(None, description="CrowdStrike device/agent ID")
    process_id: str | None = Field(None, description="Process ID for process tree queries")
    ioc_value: str | None = Field(None, description="Hash, IP, or domain to look up")
    ioc_type: Literal["sha256", "md5", "ipv4", "domain"] = Field(
        "sha256", description="IOC type for IOC lookup queries"
    )
    hours_back: int = Field(72, description="Look-back window in hours", ge=1, le=2160)


# ---------------------------------------------------------------------------
# Async implementation
# ---------------------------------------------------------------------------

@observe(name="query_crowdstrike", as_type="span")
async def crowdstrike_query_async(params: CrowdStrikeInput) -> dict[str, Any]:
    settings = get_settings()
    if not settings.crowdstrike_client_id:
        return {
            "source_available": False,
            "source": "crowdstrike",
            "error": (
                "CrowdStrike is not configured. Set CROWDSTRIKE_CLIENT_ID and "
                "CROWDSTRIKE_CLIENT_SECRET in .env (and CROWDSTRIKE_BASE_URL for your Falcon cloud)."
            ),
            "query_type": params.query_type,
        }

    start_ms = int(time.time() * 1000)
    try:
        async with httpx.AsyncClient(
            base_url=settings.crowdstrike_base_url,
            timeout=settings.tool_timeout_seconds,
        ) as client:
            token = await _get_token(client)
            headers = {"Authorization": f"Bearer {token}"}

            if params.query_type == "detections_by_host":
                return await _detections_by_host(client, headers, params)
            if params.query_type == "process_tree":
                return await _process_tree(client, headers, params)
            if params.query_type == "device_info":
                return await _device_info(client, headers, params)
            if params.query_type == "ioc_lookup":
                return await _ioc_lookup(client, headers, params)
            if params.query_type == "alerts_by_host":
                return await _alerts_by_host(client, headers, params)
            if params.query_type == "incidents_by_host":
                return await _incidents_by_host(client, headers, params)

    except httpx.TimeoutException:
        logger.warning("crowdstrike_timeout", params=params.model_dump())
        return {"source_available": False, "error": "CrowdStrike API timed out"}
    except Exception as exc:
        logger.error("crowdstrike_error", error=str(exc))
        return {"source_available": False, "error": str(exc)}

    return {"results": []}


async def _detections_by_host(
    client: httpx.AsyncClient, headers: dict, params: CrowdStrikeInput
) -> dict[str, Any]:
    fql = CrowdStrikeQueryBuilder.detections_by_host(
        params.hostname or "", params.hours_back
    )
    # Step 1: get detection IDs
    ids_resp = await client.get(
        "/detects/queries/detects/v1",
        headers=headers,
        params={"filter": fql, "limit": 50},
    )
    ids_resp.raise_for_status()
    detection_ids = ids_resp.json().get("resources", [])
    if not detection_ids:
        return {"source": "crowdstrike", "detections": [], "count": 0}

    # Step 2: get detection details
    details_resp = await client.post(
        "/detects/entities/summaries/GET/v1",
        headers=headers,
        json={"ids": detection_ids[:25]},
    )
    details_resp.raise_for_status()
    detections = details_resp.json().get("resources", [])
    return {
        "source": "crowdstrike",
        "count": len(detections),
        "detections": [
            {
                "id": d.get("detection_id"),
                "severity": d.get("max_severity_displayname"),
                "technique": d.get("technique"),
                "tactic": d.get("tactic"),
                "filename": d.get("filename"),
                "cmdline": d.get("cmdline"),
                "status": d.get("status"),
            }
            for d in detections
        ],
    }


async def _process_tree(
    client: httpx.AsyncClient, headers: dict, params: CrowdStrikeInput
) -> dict[str, Any]:
    if not params.device_id:
        return {"error": "device_id required for process_tree query"}
    resp = await client.get(
        "/processes/entities/processes/v1",
        headers=headers,
        params={"ids": params.process_id or ""},
    )
    resp.raise_for_status()
    processes = resp.json().get("resources", [])
    return {"source": "crowdstrike", "process_tree": processes}


async def _device_info(
    client: httpx.AsyncClient, headers: dict, params: CrowdStrikeInput
) -> dict[str, Any]:
    query = f"hostname:'{params.hostname}'" if params.hostname else ""
    resp = await client.get(
        "/devices/queries/devices/v1",
        headers=headers,
        params={"filter": query, "limit": 1},
    )
    resp.raise_for_status()
    device_ids = resp.json().get("resources", [])
    if not device_ids:
        return {"source": "crowdstrike", "found": False}
    details_resp = await client.get(
        "/devices/entities/devices/v2",
        headers=headers,
        params={"ids": device_ids[0]},
    )
    details_resp.raise_for_status()
    d = details_resp.json().get("resources", [{}])[0]
    return {
        "source": "crowdstrike",
        "found": True,
        "device_id": d.get("device_id"),
        "hostname": d.get("hostname"),
        "os_version": d.get("os_version"),
        "agent_version": d.get("agent_version"),
        "last_seen": d.get("last_seen"),
        "containment_status": d.get("status"),
        "groups": d.get("groups", []),
        "tags": d.get("tags", []),
    }


async def _ioc_lookup(
    client: httpx.AsyncClient, headers: dict, params: CrowdStrikeInput
) -> dict[str, Any]:
    fql = CrowdStrikeQueryBuilder.ioc_lookup(params.ioc_value or "", params.ioc_type)
    resp = await client.get(
        "/iocs/queries/indicators/v1",
        headers=headers,
        params={"filter": fql},
    )
    resp.raise_for_status()
    return {"source": "crowdstrike", "ioc_matches": resp.json().get("resources", [])}


async def _alerts_by_host(
    client: httpx.AsyncClient, headers: dict, params: CrowdStrikeInput
) -> dict[str, Any]:
    """Query CrowdStrike alerts (v2) filtered by hostname."""
    fql = f"device.hostname:'{params.hostname}'" if params.hostname else ""
    ids_resp = await client.get(
        "/alerts/queries/alerts/v2",
        headers=headers,
        params={"filter": fql, "limit": 50},
    )
    ids_resp.raise_for_status()
    alert_ids = ids_resp.json().get("resources", [])
    if not alert_ids:
        return {"source": "crowdstrike", "alerts": [], "count": 0}

    details_resp = await client.post(
        "/alerts/entities/alerts/v2",
        headers=headers,
        json={"composite_ids": alert_ids[:25]},
    )
    details_resp.raise_for_status()
    alerts = details_resp.json().get("resources", [])
    return {
        "source": "crowdstrike",
        "count": len(alerts),
        "alerts": [
            {
                "id": a.get("composite_id") or a.get("id"),
                "name": a.get("name"),
                "severity": a.get("severity_name") or a.get("severity"),
                "tactic": a.get("tactic"),
                "technique": a.get("technique"),
                "status": a.get("status"),
                "product": a.get("product"),
                "description": (a.get("description") or "")[:200],
                "created_timestamp": a.get("created_timestamp"),
            }
            for a in alerts
        ],
    }


async def _incidents_by_host(
    client: httpx.AsyncClient, headers: dict, params: CrowdStrikeInput
) -> dict[str, Any]:
    """Query CrowdStrike incidents filtered by hostname."""
    fql = f"host_ids.hostname:'{params.hostname}'" if params.hostname else ""
    ids_resp = await client.get(
        "/incidents/queries/incidents/v1",
        headers=headers,
        params={"filter": fql, "limit": 25, "sort": "start.desc"},
    )
    ids_resp.raise_for_status()
    incident_ids = ids_resp.json().get("resources", [])
    if not incident_ids:
        return {"source": "crowdstrike", "incidents": [], "count": 0}

    details_resp = await client.post(
        "/incidents/entities/incidents/GET/v1",
        headers=headers,
        json={"ids": incident_ids[:15]},
    )
    details_resp.raise_for_status()
    incidents = details_resp.json().get("resources", [])
    return {
        "source": "crowdstrike",
        "count": len(incidents),
        "incidents": [
            {
                "id": inc.get("incident_id"),
                "name": inc.get("name"),
                "description": (inc.get("description") or "")[:200],
                "status": inc.get("status"),
                "severity": inc.get("fine_score"),
                "tactics": inc.get("tactics", []),
                "techniques": inc.get("techniques", []),
                "tags": inc.get("tags", []),
                "start": inc.get("start"),
                "end": inc.get("end"),
                "host_count": len(inc.get("hosts", [])),
            }
            for inc in incidents
        ],
    }


# ---------------------------------------------------------------------------
# LangChain @tool
# ---------------------------------------------------------------------------

@tool("query_crowdstrike", args_schema=CrowdStrikeInput)
async def query_crowdstrike(
    query_type: str,
    hostname: str | None = None,
    device_id: str | None = None,
    process_id: str | None = None,
    ioc_value: str | None = None,
    ioc_type: str = "sha256",
    hours_back: int = 72,
) -> dict[str, Any]:
    """
    Query CrowdStrike Falcon for endpoint security data. Use this tool to:
    - Get all detections on a specific host (query_type='detections_by_host')
    - Retrieve the process execution tree for forensic analysis (query_type='process_tree')
    - Get device metadata: OS, agent version, containment status (query_type='device_info')
    - Check if a hash/IP/domain is a known malicious IOC in CrowdStrike (query_type='ioc_lookup')
    - Get Falcon alerts for a host with severity/tactic/technique (query_type='alerts_by_host')
    - Get correlated incidents for a host with timeline/tactics (query_type='incidents_by_host')

    Always use for T1003.001 (credential dumping), T1486 (ransomware), and T1053.005 (scheduled tasks).
    This is the highest-fidelity source for process-level forensics.
    """
    params = CrowdStrikeInput(
        query_type=query_type,  # type: ignore[arg-type]
        hostname=hostname,
        device_id=device_id,
        process_id=process_id,
        ioc_value=ioc_value,
        ioc_type=ioc_type,  # type: ignore[arg-type]
        hours_back=hours_back,
    )
    return await crowdstrike_query_async(params)
