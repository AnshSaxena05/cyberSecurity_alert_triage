"""
Content Filter — validates LLM-requested tool call parameters before execution.

Prevents prompt injection attacks where a malicious alert payload tricks the
LLM into calling tools with unexpected parameters (e.g., deleting data,
exfiltrating credentials via a 'raw_spl' query).
"""

from __future__ import annotations

import re
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

_DANGEROUS_SPL_RE = re.compile(
    r"\b(delete|drop|insert|update|output|sendemail)\b",
    re.IGNORECASE,
)
_SSRF_TARGETS = {
    "169.254.169.254",  # AWS metadata endpoint
    "metadata.google.internal",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
}


def validate_tool_params(tool_name: str, params: dict[str, Any]) -> tuple[bool, str]:
    """
    Returns (is_safe, reason).
    If is_safe is False, the tool call must be blocked.
    """
    if tool_name == "query_splunk":
        raw_spl = params.get("raw_spl", "")
        if raw_spl and _DANGEROUS_SPL_RE.search(raw_spl):
            return False, f"Dangerous SPL keyword detected in raw_spl: {raw_spl[:100]}"

    if tool_name in ("lookup_threat_intel", "query_netflow"):
        ip = params.get("ioc_value") or params.get("src_ip") or params.get("dst_ip") or ""
        if any(target in ip for target in _SSRF_TARGETS):
            return False, f"SSRF target detected in IP parameter: {ip}"

    hours_back = params.get("hours_back", 0)
    if isinstance(hours_back, int) and hours_back > 8760:  # > 1 year
        return False, f"hours_back={hours_back} exceeds maximum (8760h)"

    return True, "ok"
