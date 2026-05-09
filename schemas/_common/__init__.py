"""
Shared, stable types used across all schema versions.

Rule: this package MUST NOT import from any schemas/v* module. If a type is
not stable enough to live here, version it instead.
"""

from schemas._common.enums import AlertSource, EscalationDecision, Severity

__all__ = ["AlertSource", "EscalationDecision", "Severity"]
