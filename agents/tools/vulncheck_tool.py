"""
VulnCheck Tool — queries VulnCheck API for CVE/vulnerability intelligence.

Returns CVSS scores, exploit availability, and remediation context for CVE IDs
extracted from alerts. Useful when a detection or technique references a specific
vulnerability (e.g. exploitation of public-facing applications, T1190).

Returns source_available=false with an explicit error when VULNCHECK_API_TOKEN is not set.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import structlog
from langchain_core.tools import tool
from langfuse import observe
from pydantic import BaseModel, Field

from app.config import get_settings

logger = structlog.get_logger(__name__)

VULNCHECK_BASE = "https://api.vulncheck.com/v3"


class VulnCheckInput(BaseModel):
    cve_id: str = Field(description="CVE ID to look up, e.g. CVE-2024-1234")


@observe(name="lookup_vulncheck", as_type="span")
async def vulncheck_lookup_async(params: VulnCheckInput) -> dict[str, Any]:
    settings = get_settings()
    if not settings.vulncheck_api_token:
        return {
            "source_available": False,
            "source": "vulncheck",
            "cve_id": params.cve_id,
            "error": "VulnCheck is not configured. Set VULNCHECK_API_TOKEN in .env.",
        }

    start_ms = int(time.time() * 1000)
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {settings.vulncheck_api_token}",
    }

    try:
        async with httpx.AsyncClient(timeout=settings.tool_timeout_seconds) as client:
            resp = await client.get(
                f"{VULNCHECK_BASE}/index/vulncheck-nvd2",
                headers=headers,
                params={"cve": params.cve_id},
            )
            resp.raise_for_status()
            data = resp.json().get("data", [])
            if not data:
                return {
                    "source": "vulncheck",
                    "cve_id": params.cve_id,
                    "found": False,
                    "elapsed_ms": int(time.time() * 1000) - start_ms,
                }

            vuln = data[0]
            cve_meta = vuln.get("cve", {})
            metrics = cve_meta.get("metrics", {})

            cvss_v31 = metrics.get("cvssMetricV31", [{}])
            cvss_data = cvss_v31[0].get("cvssData", {}) if cvss_v31 else {}
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_severity = cvss_data.get("baseSeverity", "UNKNOWN")

            descriptions = cve_meta.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")[:300]
                    break

            exploit_available = bool(vuln.get("vulncheck_known_exploited"))
            references = [
                ref.get("url", "")
                for ref in cve_meta.get("references", [])[:5]
            ]

            return {
                "source": "vulncheck",
                "cve_id": params.cve_id,
                "found": True,
                "cvss_v3_score": cvss_score,
                "severity": cvss_severity,
                "description": description,
                "exploit_available": exploit_available,
                "references": references,
                "elapsed_ms": int(time.time() * 1000) - start_ms,
            }

    except httpx.TimeoutException:
        logger.warning("vulncheck_timeout", cve=params.cve_id)
        return {"source_available": False, "error": "VulnCheck API timed out"}
    except Exception as exc:
        logger.error("vulncheck_error", error=str(exc))
        return {"source_available": False, "error": str(exc)}


@tool("lookup_vulncheck", args_schema=VulnCheckInput)
async def lookup_vulncheck(
    cve_id: str,
) -> dict[str, Any]:
    """
    Look up a CVE in VulnCheck for vulnerability intelligence. Use this tool to:
    - Get CVSS v3 score and severity rating for a CVE
    - Determine if a known exploit is available in the wild
    - Get vulnerability description and reference URLs
    - Assess risk when a detection references a specific CVE

    Use for T1190 (exploit public-facing application), T1203 (exploitation for
    client execution), and T1210 (exploitation of remote services).
    """
    params = VulnCheckInput(cve_id=cve_id)
    return await vulncheck_lookup_async(params)
