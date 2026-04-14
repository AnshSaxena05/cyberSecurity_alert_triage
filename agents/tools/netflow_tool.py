"""
NetFlow / DNS Tool — queries network flow data and DNS logs.

When NDR_FLOW_API_URL is set, POSTs a JSON envelope to that HTTP endpoint and
returns the upstream JSON (caller must shape responses). Otherwise returns
source_available=false with an explicit error.
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
    "NetFlow/NDR API URL not configured. Set NDR_FLOW_API_URL (and optional NDR_FLOW_API_TOKEN) in .env."
)


class NetFlowInput(BaseModel):
    query_type: Literal[
        "dns_entropy_analysis",
        "beacon_detection",
        "top_talkers",
        "exfil_volume",
        "port_scan_detection",
    ] = Field(description="Type of network analysis to perform")
    src_ip: str | None = Field(None, description="Source IP to analyse")
    dst_ip: str | None = Field(None, description="Destination IP to analyse")
    hostname: str | None = Field(None, description="Hostname to resolve and analyse")
    hours_back: int = Field(720, description="Look-back window in hours", ge=1, le=8760)
    threshold_bytes: int = Field(
        10_000_000, description="Minimum bytes for exfil detection (default 10MB)"
    )


@observe(name="query_netflow", as_type="span")
async def netflow_query_async(params: NetFlowInput) -> dict[str, Any]:
    settings = get_settings()
    url = (settings.ndr_flow_api_url or "").strip()
    if not url:
        logger.info("netflow_tool_unconfigured", query_type=params.query_type)
        return {
            "source_available": False,
            "source": "netflow_dns",
            "query_type": params.query_type,
            "error": _UNCONFIGURED_MSG,
        }

    body = {
        "query_type": params.query_type,
        "src_ip": params.src_ip,
        "dst_ip": params.dst_ip,
        "hostname": params.hostname,
        "hours_back": params.hours_back,
        "threshold_bytes": params.threshold_bytes,
    }
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if settings.ndr_flow_api_token:
        headers["Authorization"] = f"Bearer {settings.ndr_flow_api_token}"

    try:
        async with httpx.AsyncClient(
            timeout=settings.tool_timeout_seconds,
            verify=True,
        ) as client:
            resp = await client.post(url, json=body, headers=headers)
            if resp.status_code >= 400:
                return {
                    "source_available": False,
                    "source": "netflow_dns",
                    "error": f"NDR HTTP {resp.status_code}: {resp.text[:300]}",
                }
            data = resp.json()
            if isinstance(data, dict):
                data.setdefault("source_available", True)
                data.setdefault("source", "netflow_dns")
                data.setdefault("query_type", params.query_type)
                return data
            return {
                "source_available": True,
                "source": "netflow_dns",
                "query_type": params.query_type,
                "raw": data,
            }
    except httpx.TimeoutException:
        return {"source_available": False, "source": "netflow_dns", "error": "NDR API timed out"}
    except Exception as exc:
        logger.error("netflow_ndr_error", error=str(exc))
        return {"source_available": False, "source": "netflow_dns", "error": str(exc)}


@tool("query_netflow", args_schema=NetFlowInput)
async def query_netflow(
    query_type: str,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    hostname: str | None = None,
    hours_back: int = 720,
    threshold_bytes: int = 10_000_000,
) -> dict[str, Any]:
    """
    Query network flow and DNS log data for threat detection. Use this tool to:
    - Detect DNS tunnelling via Shannon entropy analysis (query_type='dns_entropy_analysis')
    - Detect C2 beaconing via periodic connection analysis (query_type='beacon_detection')
    - Find the highest-volume network conversations (query_type='top_talkers')
    - Detect data exfiltration by volume (query_type='exfil_volume')
    - Detect lateral port scanning (query_type='port_scan_detection')

    Primary tool for T1071.004 (DNS tunnelling), T1573 (encrypted C2), T1048 (exfiltration).
    """
    params = NetFlowInput(
        query_type=query_type,  # type: ignore[arg-type]
        src_ip=src_ip,
        dst_ip=dst_ip,
        hostname=hostname,
        hours_back=hours_back,
        threshold_bytes=threshold_bytes,
    )
    return await netflow_query_async(params)


@tool("query_dns_logs", args_schema=NetFlowInput)
async def query_dns_logs(
    query_type: str = "dns_entropy_analysis",
    src_ip: str | None = None,
    dst_ip: str | None = None,
    hostname: str | None = None,
    hours_back: int = 720,
    threshold_bytes: int = 10_000_000,
) -> dict[str, Any]:
    """
    Alias for netflow focusing specifically on DNS query logs.
    Use for T1071.004 (DNS Application Layer Protocol) alerts.
    """
    return await query_netflow(
        query_type=query_type,
        src_ip=src_ip,
        dst_ip=dst_ip,
        hostname=hostname,
        hours_back=hours_back,
        threshold_bytes=threshold_bytes,
    )
