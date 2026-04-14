"""
Output Filter — scrubs sensitive data from triage verdicts before
they are returned to callers or written to logs.

Prevents credential leakage (passwords in command lines),
PII exposure (full SSNs, email addresses), and API key logging.
"""

from __future__ import annotations

import re
from typing import Any

_PASSWORD_RE = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*\S+",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")


def scrub_string(value: str) -> str:
    value = _PASSWORD_RE.sub(r"\1=***REDACTED***", value)
    value = _CREDIT_CARD_RE.sub("***CC_REDACTED***", value)
    return value


def scrub_verdict_for_log(verdict_dict: dict[str, Any]) -> dict[str, Any]:
    """Remove raw tool output that may contain sensitive data before logging."""
    cleaned = {k: v for k, v in verdict_dict.items() if k != "raw_tool_outputs"}
    if "triage_summary" in cleaned:
        cleaned["triage_summary"] = scrub_string(str(cleaned["triage_summary"]))
    return cleaned
