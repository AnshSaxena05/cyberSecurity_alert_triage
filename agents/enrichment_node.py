"""
Burst Enrichment Node — Phase 1 of the deep triage path.

Fires ALL tools prescribed by the MITRE routing table in parallel using
asyncio.gather(). Results are compressed before insertion into the LangGraph
state to keep the LLM's context window budget under control.

This replicates Vega.io's Mode 2 federated query burst:
  → All known-relevant sources queried simultaneously
  → Results normalised to a compact summary
  → LLM sees aggregated context, not raw API payloads

Context compression strategy:
  - Each tool's raw response is summarised to ≤200 tokens
  - Only key security-relevant fields are forwarded
  - Full raw results are stored separately (for analyst review, not LLM consumption)
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog
from langfuse import observe

from app.models import ExtractedEntities, NormalizedAlert, ToolCallRecord
from services.mitre_router import get_tools_for_techniques, get_time_window
from services.context_cache import get_cache

logger = structlog.get_logger(__name__)

# Registry maps tool name strings → async callables
# Populated at module load to avoid circular imports
_TOOL_REGISTRY: dict[str, Any] = {}


def _get_tool_registry() -> dict[str, Any]:
    global _TOOL_REGISTRY
    if not _TOOL_REGISTRY:
        from agents.tools.splunk_tool import splunk_query_async, SplunkQueryInput
        from agents.tools.crowdstrike_tool import crowdstrike_query_async, CrowdStrikeInput
        from agents.tools.threat_intel_tool import threat_intel_lookup_async, ThreatIntelInput
        from agents.tools.aws_tool import aws_query_async, AWSQueryInput
        from agents.tools.cmdb_tool import cmdb_query_async, CMDBInput
        from agents.tools.netflow_tool import netflow_query_async, NetFlowInput
        from agents.tools.backup_tool import backup_query_async, BackupQueryInput
        from agents.tools.vulncheck_tool import vulncheck_lookup_async, VulnCheckInput

        _TOOL_REGISTRY = {
            "query_splunk": (splunk_query_async, SplunkQueryInput),
            "query_crowdstrike": (crowdstrike_query_async, CrowdStrikeInput),
            "lookup_threat_intel": (threat_intel_lookup_async, ThreatIntelInput),
            "query_aws": (aws_query_async, AWSQueryInput),
            "query_cmdb": (cmdb_query_async, CMDBInput),
            "query_netflow": (netflow_query_async, NetFlowInput),
            "query_dns_logs": (netflow_query_async, NetFlowInput),
            "query_backup_systems": (backup_query_async, BackupQueryInput),
            "lookup_vulncheck": (vulncheck_lookup_async, VulnCheckInput),
        }
    return _TOOL_REGISTRY


# ---------------------------------------------------------------------------
# Parameter builders — translate alert entities into tool-specific inputs
# ---------------------------------------------------------------------------

def _build_splunk_params(
    alert: NormalizedAlert, entities: ExtractedEntities, technique_id: str
) -> dict[str, Any]:
    tw = get_time_window(technique_id)
    hostname = entities.hosts[0].hostname if entities.hosts else alert.hostname
    username = entities.users[0].username if entities.users else None
    ip = entities.iocs[0].value if entities.iocs and entities.iocs[0].type == "ip" else None

    # Pick the most relevant Splunk query type for this technique
    if technique_id.startswith("T1110"):
        return {"query_type": "auth_events_by_user", "username": username, "hours_back": tw.hours}
    if technique_id.startswith("T1486") or technique_id.startswith("T1490"):
        return {"query_type": "shadow_copy_deletion", "hours_back": tw.hours}
    if technique_id.startswith("T1053"):
        return {"query_type": "scheduled_tasks", "hostname": hostname, "hours_back": tw.hours}
    if technique_id.startswith("T1071"):
        return {"query_type": "dns_tunneling", "hostname": hostname, "hours_back": tw.hours}
    return {"query_type": "process_by_host", "hostname": hostname, "hours_back": tw.hours}


def _build_crowdstrike_params(
    alert: NormalizedAlert, entities: ExtractedEntities, technique_id: str
) -> dict[str, Any]:
    hostname = entities.hosts[0].hostname if entities.hosts else alert.hostname
    tw = get_time_window(technique_id)
    return {"query_type": "detections_by_host", "hostname": hostname, "hours_back": tw.hours}


def _build_threat_intel_params(
    alert: NormalizedAlert, entities: ExtractedEntities, technique_id: str
) -> dict[str, Any]:
    # Prefer hash IOCs for file-based techniques, IP for network techniques
    for ioc in entities.iocs:
        if ioc.type == "hash_sha256":
            return {"ioc_type": "hash_sha256", "ioc_value": ioc.value}
        if ioc.type == "ip":
            return {"ioc_type": "ip", "ioc_value": ioc.value}
    # Fall back to alert network data
    if alert.network and alert.network.dst_ip:
        return {"ioc_type": "ip", "ioc_value": alert.network.dst_ip}
    return None  # type: ignore[return-value]


def _build_netflow_params(
    alert: NormalizedAlert, entities: ExtractedEntities, technique_id: str
) -> dict[str, Any]:
    tw = get_time_window(technique_id)
    src_ip = alert.network.src_ip if alert.network else None
    hostname = entities.hosts[0].hostname if entities.hosts else alert.hostname
    if technique_id.startswith("T1071.004"):
        return {"query_type": "dns_entropy_analysis", "src_ip": src_ip, "hostname": hostname, "hours_back": tw.hours}
    if technique_id.startswith("T1573") or technique_id.startswith("T1095"):
        return {"query_type": "beacon_detection", "src_ip": src_ip, "hours_back": tw.hours}
    return {"query_type": "top_talkers", "src_ip": src_ip, "hours_back": tw.hours}


def _build_aws_params(
    alert: NormalizedAlert, entities: ExtractedEntities, technique_id: str
) -> dict[str, Any]:
    tw = get_time_window(technique_id)
    username = entities.users[0].username if entities.users else None
    return {"query_type": "cloudtrail_by_user", "username": username, "hours_back": tw.hours}


def _build_cmdb_params(
    alert: NormalizedAlert, entities: ExtractedEntities, technique_id: str
) -> dict[str, Any]:
    hostname = entities.hosts[0].hostname if entities.hosts else alert.hostname
    if hostname:
        return {"lookup_type": "by_hostname", "hostname": hostname}
    if alert.network and alert.network.dst_ip:
        return {"lookup_type": "by_ip", "ip_address": alert.network.dst_ip}
    return {"lookup_type": "by_hostname", "hostname": "unknown"}


def _build_backup_params(
    alert: NormalizedAlert, entities: ExtractedEntities, technique_id: str
) -> dict[str, Any]:
    hostname = entities.hosts[0].hostname if entities.hosts else alert.hostname
    return {"query_type": "shadow_copy_status", "hostname": hostname}


def _build_vulncheck_params(
    alert: NormalizedAlert, entities: ExtractedEntities, technique_id: str
) -> dict[str, Any] | None:
    """Extract a CVE ID from IOCs or alert metadata for VulnCheck lookup."""
    import re
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

    for ioc in entities.iocs:
        if ioc.type == "cve":
            return {"cve_id": ioc.value}
        m = cve_pattern.search(ioc.value)
        if m:
            return {"cve_id": m.group(0).upper()}

    for field in (alert.title, alert.description):
        if field:
            m = cve_pattern.search(field)
            if m:
                return {"cve_id": m.group(0).upper()}

    return None


_PARAM_BUILDERS = {
    "query_splunk": _build_splunk_params,
    "query_crowdstrike": _build_crowdstrike_params,
    "lookup_threat_intel": _build_threat_intel_params,
    "query_aws": _build_aws_params,
    "query_cmdb": _build_cmdb_params,
    "query_netflow": _build_netflow_params,
    "query_dns_logs": _build_netflow_params,
    "query_backup_systems": _build_backup_params,
    "lookup_vulncheck": _build_vulncheck_params,
}


# ---------------------------------------------------------------------------
# Context compression
# ---------------------------------------------------------------------------

def compress_tool_result(tool_name: str, result: dict[str, Any]) -> str:
    """Reduce a raw tool result to a compact string for LLM consumption."""
    if result.get("error"):
        return f"[{tool_name}] ERROR: {result['error']}"
    if result.get("source_available") is False:
        return f"[{tool_name}] ERROR: {result.get('error', 'source unavailable')}"

    # Source-specific compression
    if tool_name == "query_splunk":
        return (
            f"[Splunk/{result.get('query_type', '?')}] "
            f"{result.get('result_count', 0)} results. "
            f"Summary: {result.get('summary', 'No summary.')}"
        )
    if tool_name == "query_crowdstrike":
        detections = result.get("detections", [])
        if detections:
            top = detections[0]
            return (
                f"[CrowdStrike] {result.get('count', 0)} detections. "
                f"Top: {top.get('technique')} ({top.get('severity')}) — {top.get('filename')}"
            )
        alerts = result.get("alerts", [])
        if alerts:
            top = alerts[0]
            return (
                f"[CrowdStrike/Alerts] {result.get('count', 0)} alerts. "
                f"Top: {top.get('technique')} ({top.get('severity')}) — {top.get('name', '?')}"
            )
        incidents = result.get("incidents", [])
        if incidents:
            top = incidents[0]
            tactics = ", ".join(top.get("tactics", [])[:3]) or "N/A"
            return (
                f"[CrowdStrike/Incidents] {result.get('count', 0)} incidents. "
                f"Top: severity={top.get('severity')} tactics={tactics} hosts={top.get('host_count', '?')}"
            )
        return f"[CrowdStrike] {result.get('count', 0)} results."

    if tool_name == "lookup_threat_intel":
        return (
            f"[ThreatIntel] IOC={result.get('ioc')} "
            f"Verdict={result.get('verdict')} — {result.get('detail', '')}"
        )

    if tool_name in ("query_netflow", "query_dns_logs"):
        return (
            f"[NetFlow/{result.get('query_type', '?')}] "
            f"Verdict={result.get('verdict', 'N/A')}. "
            f"Bytes={result.get('total_bytes_dns', result.get('total_bytes_out', 'N/A'))}. "
            f"High-entropy queries={result.get('high_entropy_queries', 'N/A')}"
        )

    if tool_name == "query_cmdb":
        if not result.get("found", True):
            return f"[CMDB] {result.get('hostname', '?')} — no matching CI in ServiceNow"
        return (
            f"[CMDB] {result.get('hostname')} — "
            f"criticality={result.get('criticality')} "
            f"type={result.get('asset_type')} "
            f"zone={result.get('network_zone')}"
        )

    if tool_name == "query_aws":
        high_risk = result.get("high_risk_events", [])
        return (
            f"[AWS] {result.get('total_events', 0)} CloudTrail events. "
            f"{len(high_risk)} high-risk IAM events: "
            f"{', '.join(e.get('EventName','?') for e in high_risk[:3])}"
        )

    if tool_name == "query_backup_systems":
        return (
            f"[Backup] Shadow copies exist={result.get('shadow_copies_exist')} "
            f"Verdict={result.get('verdict', 'N/A')}"
        )

    if tool_name == "lookup_vulncheck":
        if not result.get("found"):
            return f"[VulnCheck] {result.get('cve_id', '?')} — not found"
        exploit = "yes" if result.get("exploit_available") else "no"
        return (
            f"[VulnCheck] {result.get('cve_id')} "
            f"CVSS={result.get('cvss_v3_score', '?')} ({result.get('severity', '?')}) "
            f"exploit={exploit}"
        )

    # Generic fallback
    return f"[{tool_name}] {str(result)[:300]}"


# ---------------------------------------------------------------------------
# Single tool execution with cache + timeout
# ---------------------------------------------------------------------------

@observe(name="tool_execution", as_type="span")
async def _execute_single_tool(
    tool_name: str,
    params: dict[str, Any],
    timeout_seconds: int = 30,
) -> tuple[str, dict[str, Any], ToolCallRecord]:
    start_ms = int(time.time() * 1000)
    registry = _get_tool_registry()
    cache = get_cache()

    # Cache check
    cached = await cache.get(tool_name, params)
    if cached:
        compressed = compress_tool_result(tool_name, cached)
        record = ToolCallRecord(
            tool_name=tool_name,
            input_params=params,
            result_summary=compressed + " [CACHED]",
            raw_result=cached,
            latency_ms=0,
        )
        return tool_name, cached, record

    if tool_name not in registry:
        result = {"error": f"Tool '{tool_name}' not registered", "source_available": False}
        record = ToolCallRecord(
            tool_name=tool_name,
            input_params=params,
            result_summary=f"[{tool_name}] NOT REGISTERED",
            raw_result=result,
            latency_ms=0,
            error=result["error"],
        )
        return tool_name, result, record

    fn, schema_cls = registry[tool_name]
    try:
        typed_params = schema_cls(**params)
        result = await asyncio.wait_for(fn(typed_params), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        result = {"source_available": False, "error": f"Timeout after {timeout_seconds}s"}
    except Exception as exc:
        logger.error("tool_execution_error", tool=tool_name, error=str(exc))
        result = {"source_available": False, "error": str(exc)}

    # Cache the result
    if result.get("source_available", True) and not result.get("error"):
        await cache.set(tool_name, params, result)

    elapsed = int(time.time() * 1000) - start_ms
    compressed = compress_tool_result(tool_name, result)
    record = ToolCallRecord(
        tool_name=tool_name,
        input_params=params,
        result_summary=compressed,
        raw_result=result,
        latency_ms=elapsed,
        source_available=result.get("source_available", True),
        error=result.get("error"),
    )
    logger.info("tool_executed", tool=tool_name, elapsed_ms=elapsed, cached=False)
    return tool_name, result, record


# ---------------------------------------------------------------------------
# Burst enrichment — fire all tools in parallel
# ---------------------------------------------------------------------------

@observe(name="burst_enrichment", as_type="span", capture_input=False)
async def run_burst_enrichment(
    alert: NormalizedAlert,
    entities: ExtractedEntities,
    technique_ids: list[str],
    timeout_seconds: int = 30,
) -> tuple[dict[str, Any], list[ToolCallRecord]]:
    """
    Fire all prescribed tools in parallel for the given technique IDs.
    Returns (enrichment_data_dict, list_of_tool_call_records).
    """
    tool_names = get_tools_for_techniques(technique_ids)
    if not tool_names:
        logger.warning("no_tools_for_techniques", technique_ids=technique_ids)
        return {}, []

    logger.info("burst_enrichment_start", tools=tool_names, techniques=technique_ids)

    tasks = []
    for tool_name in tool_names:
        param_builder = _PARAM_BUILDERS.get(tool_name)
        if not param_builder:
            continue
        # Build params using the primary technique (first match)
        primary_technique = technique_ids[0] if technique_ids else "T1082"
        try:
            params = param_builder(alert, entities, primary_technique)
        except Exception:
            params = {}
        if params is not None:
            tasks.append(_execute_single_tool(tool_name, params, timeout_seconds))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    enrichment_data: dict[str, Any] = {}
    records: list[ToolCallRecord] = []

    for res in results:
        if isinstance(res, Exception):
            logger.error("burst_task_exception", error=str(res))
            continue
        tool_name, data, record = res
        enrichment_data[tool_name] = data
        records.append(record)

    logger.info(
        "burst_enrichment_complete",
        tools_fired=len(records),
        tools_succeeded=sum(1 for r in records if not r.error),
    )
    return enrichment_data, records
