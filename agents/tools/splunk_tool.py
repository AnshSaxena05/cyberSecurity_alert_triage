"""
Splunk Tool — queries Splunk REST API via SPL.

The LangChain @tool decorator exposes this to the LangGraph agent with a
fully-typed Pydantic input schema. The docstring is what the LLM reads
to decide when to invoke this tool.

For the burst enrichment phase, call splunk_query_async directly.
"""

from __future__ import annotations

import asyncio
import time
from typing import Annotated, Any, Literal

import httpx
import structlog
from langchain_core.tools import tool
from langfuse import observe
from pydantic import BaseModel, Field

from app.config import get_settings
from services.query_builder import SPLBuilder

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Input schema (Pydantic — LLM must match this exactly)
# ---------------------------------------------------------------------------

class SplunkQueryInput(BaseModel):
    query_type: Annotated[
        Literal[
            "process_by_host",
            "auth_events_by_user",
            "network_by_ip",
            "dns_tunneling",
            "scheduled_tasks",
            "shadow_copy_deletion",
            "file_rename_burst",
            "raw_spl",
        ],
        Field(description="Type of pre-built query to run, or 'raw_spl' for a custom SPL string"),
    ]
    hostname: str | None = Field(None, description="Target hostname to search")
    username: str | None = Field(None, description="Target username for auth event queries")
    ip_address: str | None = Field(None, description="IP address for network queries")
    hours_back: int = Field(72, description="How many hours back to search", ge=1, le=8760)
    raw_spl: str | None = Field(
        None,
        description="Only set when query_type='raw_spl'. Must be a valid SPL query.",
    )
    max_results: int = Field(100, description="Maximum number of results to return", ge=1, le=1000)


# ---------------------------------------------------------------------------
# Async implementation
# ---------------------------------------------------------------------------

@observe(name="query_splunk", as_type="span")
async def splunk_query_async(params: SplunkQueryInput) -> dict[str, Any]:
    """Execute a Splunk search and return compressed results."""
    settings = get_settings()
    start_ms = int(time.time() * 1000)

    spl = _build_spl(params)
    if not spl:
        return {"error": "Could not build SPL query from provided parameters", "results": []}

    auth = (settings.splunk_username, settings.splunk_password)
    token_headers = (
        {"Authorization": f"Bearer {settings.splunk_token}"}
        if settings.splunk_token
        else {}
    )
    base = f"{settings.splunk_scheme}://{settings.splunk_host}:{settings.splunk_port}"

    try:
        async with httpx.AsyncClient(
            verify=settings.splunk_verify_ssl,
            timeout=settings.tool_timeout_seconds,
        ) as client:
            # Step 1: Create search job
            create_resp = await client.post(
                f"{base}/services/search/jobs",
                data={"search": f"search {spl}", "output_mode": "json", "count": params.max_results},
                auth=auth if not settings.splunk_token else None,
                headers=token_headers,
            )
            create_resp.raise_for_status()
            sid = create_resp.json()["sid"]

            # Step 2: Poll until done
            for _ in range(30):
                await asyncio.sleep(1)
                status_resp = await client.get(
                    f"{base}/services/search/jobs/{sid}",
                    params={"output_mode": "json"},
                    auth=auth if not settings.splunk_token else None,
                    headers=token_headers,
                )
                status_resp.raise_for_status()
                dispatch_state = status_resp.json()["entry"][0]["content"]["dispatchState"]
                if dispatch_state == "DONE":
                    break

            # Step 3: Fetch results
            results_resp = await client.get(
                f"{base}/services/search/jobs/{sid}/results",
                params={"output_mode": "json", "count": params.max_results},
                auth=auth if not settings.splunk_token else None,
                headers=token_headers,
            )
            results_resp.raise_for_status()
            raw_results = results_resp.json().get("results", [])

    except httpx.TimeoutException:
        logger.warning("splunk_timeout", spl=spl[:100])
        return {"source_available": False, "error": "Splunk query timed out", "results": []}
    except Exception as exc:
        logger.error("splunk_error", error=str(exc))
        return {"source_available": False, "error": str(exc), "results": []}

    elapsed = int(time.time() * 1000) - start_ms
    compressed = _compress_results(raw_results, params.query_type)
    logger.info("splunk_query_complete", rows=len(raw_results), elapsed_ms=elapsed)
    return {
        "source": "splunk",
        "query_type": params.query_type,
        "result_count": len(raw_results),
        "elapsed_ms": elapsed,
        "summary": compressed,
        "results": raw_results[:20],  # cap raw rows sent to LLM context
    }


def _build_spl(params: SplunkQueryInput) -> str | None:
    if params.query_type == "raw_spl":
        return params.raw_spl
    if params.query_type == "process_by_host" and params.hostname:
        return SPLBuilder.process_by_host(params.hostname, params.hours_back)
    if params.query_type == "auth_events_by_user" and params.username:
        return SPLBuilder.auth_events_by_user(params.username, params.hours_back)
    if params.query_type == "network_by_ip" and params.ip_address:
        return SPLBuilder.network_by_ip(params.ip_address, params.hours_back)
    if params.query_type == "dns_tunneling" and params.hostname:
        return SPLBuilder.dns_tunneling(params.hostname, params.hours_back)
    if params.query_type == "scheduled_tasks" and params.hostname:
        return SPLBuilder.scheduled_tasks(params.hostname, params.hours_back)
    if params.query_type == "shadow_copy_deletion":
        return SPLBuilder.shadow_copy_deletion(params.hours_back)
    if params.query_type == "file_rename_burst" and params.hostname:
        return SPLBuilder.file_rename_burst(params.hostname, params.hours_back)
    return None


def _compress_results(results: list[dict], query_type: str) -> str:
    """Summarise raw Splunk results to a compact string for LLM context."""
    if not results:
        return "No results found."
    if query_type == "auth_events_by_user":
        unique_ips = {r.get("src_ip", "?") for r in results}
        failed = sum(1 for r in results if r.get("EventCode") == "4625")
        return (
            f"{len(results)} auth events | {len(unique_ips)} unique source IPs | "
            f"{failed} failed logins | IPs: {', '.join(list(unique_ips)[:5])}"
        )
    if query_type == "file_rename_burst":
        top = sorted(results, key=lambda r: int(r.get("renames", 0)), reverse=True)[:3]
        return "File renames by extension: " + ", ".join(
            f"{r.get('extension')}={r.get('renames')}" for r in top
        )
    return f"{len(results)} results returned."


# ---------------------------------------------------------------------------
# LangChain @tool — this is what the LangGraph agent calls
# ---------------------------------------------------------------------------

@tool("query_splunk", args_schema=SplunkQueryInput)
async def query_splunk(
    query_type: str,
    hostname: str | None = None,
    username: str | None = None,
    ip_address: str | None = None,
    hours_back: int = 72,
    raw_spl: str | None = None,
    max_results: int = 100,
) -> dict[str, Any]:
    """
    Query Splunk for security events. Use this tool to:
    - Retrieve process execution history for a host (query_type='process_by_host')
    - Retrieve authentication events for a user (query_type='auth_events_by_user')
    - Retrieve network connections for an IP (query_type='network_by_ip')
    - Detect DNS tunnelling patterns (query_type='dns_tunneling')
    - Find scheduled task creation events (query_type='scheduled_tasks')
    - Detect shadow copy deletion (query_type='shadow_copy_deletion')
    - Detect mass file renames indicating ransomware (query_type='file_rename_burst')
    - Run a custom SPL query (query_type='raw_spl')

    Always specify hours_back based on the signal type:
    - Process/execution events: 72h
    - Auth/login events: 336h (14 days)
    - C2 beaconing: 720h (30 days)
    - Persistence: 2160h (90 days)
    """
    params = SplunkQueryInput(
        query_type=query_type,  # type: ignore[arg-type]
        hostname=hostname,
        username=username,
        ip_address=ip_address,
        hours_back=hours_back,
        raw_spl=raw_spl,
        max_results=max_results,
    )
    return await splunk_query_async(params)
