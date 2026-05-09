"""Stable enumerations shared across schema versions."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertSource(StrEnum):
    SPLUNK = "splunk"
    CROWDSTRIKE = "crowdstrike"
    AWS_GUARDDUTY = "aws_guardduty"
    SENTINEL = "sentinel"
    GENERIC = "generic"


class EscalationDecision(StrEnum):
    ESCALATE_IR = "ESCALATE_IR"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    MONITOR = "MONITOR"
    CLOSE = "CLOSE"
