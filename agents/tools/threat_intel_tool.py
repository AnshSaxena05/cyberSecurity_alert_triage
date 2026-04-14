"""
Threat Intelligence Tool — queries VirusTotal, AbuseIPDB, and AlienVault OTX.

Runs all three sources in parallel (asyncio.gather) and merges verdicts.
Returns a normalised reputation summary rather than raw API responses,
keeping LLM context consumption bounded.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Literal

import httpx
import structlog
from langchain_core.tools import tool
from langfuse import observe
from pydantic import BaseModel, Field

from app.config import get_settings

logger = structlog.get_logger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
OTX_BASE = "https://otx.alienvault.com/api/v1"


# ---------------------------------------------------------------------------
# Input schema
# ---------------------------------------------------------------------------

class ThreatIntelInput(BaseModel):
    ioc_type: Annotated[
        Literal["ip", "domain", "hash_sha256", "hash_md5", "url"],
        Field(description="Type of indicator of compromise"),
    ]
    ioc_value: str = Field(description="The IOC value to look up")
    sources: list[Literal["virustotal", "abuseipdb", "otx"]] = Field(
        default=["virustotal", "abuseipdb", "otx"],
        description="Which threat intel sources to query",
    )


# ---------------------------------------------------------------------------
# Per-source query functions
# ---------------------------------------------------------------------------

async def _query_virustotal(
    client: httpx.AsyncClient, ioc_type: str, ioc_value: str, api_key: str
) -> dict[str, Any]:
    if not api_key:
        return {"source": "virustotal", "skipped": True, "reason": "no_api_key"}
    headers = {"x-apikey": api_key}
    try:
        if ioc_type == "ip":
            url = f"{VT_BASE}/ip_addresses/{ioc_value}"
        elif ioc_type == "domain":
            url = f"{VT_BASE}/domains/{ioc_value}"
        elif ioc_type in ("hash_sha256", "hash_md5"):
            url = f"{VT_BASE}/files/{ioc_value}"
        elif ioc_type == "url":
            import base64
            encoded = base64.urlsafe_b64encode(ioc_value.encode()).rstrip(b"=").decode()
            url = f"{VT_BASE}/urls/{encoded}"
        else:
            return {"source": "virustotal", "skipped": True, "reason": "unsupported_type"}

        resp = await client.get(url, headers=headers)
        if resp.status_code == 404:
            return {"source": "virustotal", "found": False, "ioc": ioc_value}
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "source": "virustotal",
            "found": True,
            "ioc": ioc_value,
            "malicious_votes": stats.get("malicious", 0),
            "suspicious_votes": stats.get("suspicious", 0),
            "harmless_votes": stats.get("harmless", 0),
            "total_engines": sum(stats.values()),
            "reputation": data.get("reputation", 0),
            "tags": data.get("tags", [])[:5],
            "categories": list(data.get("categories", {}).values())[:3],
        }
    except httpx.TimeoutException:
        return {"source": "virustotal", "error": "timeout", "ioc": ioc_value}
    except Exception as exc:
        return {"source": "virustotal", "error": str(exc), "ioc": ioc_value}


async def _query_abuseipdb(
    client: httpx.AsyncClient, ioc_value: str, api_key: str
) -> dict[str, Any]:
    if not api_key:
        return {"source": "abuseipdb", "skipped": True, "reason": "no_api_key"}
    try:
        resp = await client.get(
            f"{ABUSEIPDB_BASE}/check",
            params={"ipAddress": ioc_value, "maxAgeInDays": 90, "verbose": False},
            headers={"Key": api_key, "Accept": "application/json"},
        )
        if resp.status_code == 422:
            return {"source": "abuseipdb", "found": False, "reason": "not_an_ip"}
        resp.raise_for_status()
        d = resp.json().get("data", {})
        return {
            "source": "abuseipdb",
            "found": True,
            "ioc": ioc_value,
            "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "country_code": d.get("countryCode"),
            "isp": d.get("isp"),
            "usage_type": d.get("usageType"),
            "is_tor": d.get("isTor", False),
        }
    except httpx.TimeoutException:
        return {"source": "abuseipdb", "error": "timeout", "ioc": ioc_value}
    except Exception as exc:
        return {"source": "abuseipdb", "error": str(exc), "ioc": ioc_value}


async def _query_otx(
    client: httpx.AsyncClient, ioc_type: str, ioc_value: str, api_key: str
) -> dict[str, Any]:
    if not api_key:
        return {"source": "otx", "skipped": True, "reason": "no_api_key"}
    type_map = {
        "ip": "IPv4",
        "domain": "domain",
        "hash_sha256": "file",
        "hash_md5": "file",
        "url": "URL",
    }
    otx_type = type_map.get(ioc_type)
    if not otx_type:
        return {"source": "otx", "skipped": True, "reason": "unsupported_type"}
    try:
        resp = await client.get(
            f"{OTX_BASE}/indicators/{otx_type}/{ioc_value}/general",
            headers={"X-OTX-API-KEY": api_key},
        )
        if resp.status_code == 404:
            return {"source": "otx", "found": False, "ioc": ioc_value}
        resp.raise_for_status()
        data = resp.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        pulse_names = [
            p.get("name") for p in data.get("pulse_info", {}).get("pulses", [])[:3]
        ]
        return {
            "source": "otx",
            "found": True,
            "ioc": ioc_value,
            "pulse_count": pulses,
            "related_pulses": pulse_names,
            "indicator_type": otx_type,
        }
    except httpx.TimeoutException:
        return {"source": "otx", "error": "timeout", "ioc": ioc_value}
    except Exception as exc:
        return {"source": "otx", "error": str(exc), "ioc": ioc_value}


# ---------------------------------------------------------------------------
# Verdict merger
# ---------------------------------------------------------------------------

def _merge_verdicts(results: list[dict[str, Any]], ioc_value: str) -> dict[str, Any]:
    """Synthesise a single reputation verdict from multiple source results."""
    malicious_signals = 0
    details = []

    for r in results:
        if r.get("skipped") or r.get("error"):
            continue
        if not r.get("found"):
            details.append(f"{r['source']}: not found")
            continue

        if r["source"] == "virustotal":
            mal = r.get("malicious_votes", 0)
            total = r.get("total_engines", 1)
            details.append(f"VT: {mal}/{total} engines flagged")
            if mal >= 3:
                malicious_signals += 2
            elif mal >= 1:
                malicious_signals += 1

        elif r["source"] == "abuseipdb":
            score = r.get("abuse_confidence_score", 0)
            details.append(f"AbuseIPDB: {score}% confidence, {r.get('total_reports')} reports")
            if score >= 80:
                malicious_signals += 2
            elif score >= 30:
                malicious_signals += 1

        elif r["source"] == "otx":
            pulses = r.get("pulse_count", 0)
            details.append(f"OTX: {pulses} threat pulses")
            if pulses >= 5:
                malicious_signals += 2
            elif pulses >= 1:
                malicious_signals += 1

    if malicious_signals >= 4:
        verdict = "CONFIRMED_MALICIOUS"
    elif malicious_signals >= 2:
        verdict = "SUSPICIOUS"
    elif malicious_signals >= 1:
        verdict = "LOW_RISK"
    else:
        verdict = "CLEAN"

    return {
        "ioc": ioc_value,
        "verdict": verdict,
        "malicious_signal_count": malicious_signals,
        "detail": " | ".join(details) or "No data from any source",
        "raw_sources": results,
    }


# ---------------------------------------------------------------------------
# Async implementation
# ---------------------------------------------------------------------------

@observe(name="lookup_threat_intel", as_type="span")
async def threat_intel_lookup_async(params: ThreatIntelInput) -> dict[str, Any]:
    settings = get_settings()
    start_ms = int(time.time() * 1000)
    tasks = []

    async with httpx.AsyncClient(timeout=settings.tool_timeout_seconds) as client:
        if "virustotal" in params.sources:
            tasks.append(
                _query_virustotal(client, params.ioc_type, params.ioc_value, settings.virustotal_api_key)
            )
        if "abuseipdb" in params.sources and params.ioc_type == "ip":
            tasks.append(
                _query_abuseipdb(client, params.ioc_value, settings.abuseipdb_api_key)
            )
        if "otx" in params.sources:
            tasks.append(
                _query_otx(client, params.ioc_type, params.ioc_value, settings.otx_api_key)
            )

        source_results = await asyncio.gather(*tasks)

    elapsed = int(time.time() * 1000) - start_ms
    merged = _merge_verdicts(list(source_results), params.ioc_value)
    merged["elapsed_ms"] = elapsed
    logger.info(
        "threat_intel_complete",
        ioc=params.ioc_value,
        verdict=merged["verdict"],
        elapsed_ms=elapsed,
    )
    return merged


# ---------------------------------------------------------------------------
# LangChain @tool
# ---------------------------------------------------------------------------

from typing import Annotated  # noqa: E402 (needed after top-level imports)


@tool("lookup_threat_intel", args_schema=ThreatIntelInput)
async def lookup_threat_intel(
    ioc_type: str,
    ioc_value: str,
    sources: list[str] | None = None,
) -> dict[str, Any]:
    """
    Look up an Indicator of Compromise (IOC) against threat intelligence sources.
    Use this tool to check whether an IP address, domain, file hash, or URL
    has been reported as malicious by the security community.

    When to use:
    - Any external IP address seen in the alert
    - Any file hash (SHA256/MD5) from a suspicious process
    - Any domain involved in DNS activity or C2 communication
    - Always use for T1071.004 (DNS tunnelling) and T1486 (ransomware) alerts

    Returns a merged verdict: CONFIRMED_MALICIOUS / SUSPICIOUS / LOW_RISK / CLEAN
    with supporting detail from each source.
    """
    params = ThreatIntelInput(
        ioc_type=ioc_type,  # type: ignore[arg-type]
        ioc_value=ioc_value,
        sources=sources or ["virustotal", "abuseipdb", "otx"],
    )
    return await threat_intel_lookup_async(params)
