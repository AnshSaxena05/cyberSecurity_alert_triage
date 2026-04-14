"""
Online Monitor — tracks live pipeline accuracy and performance.

Compares pipeline verdicts against the golden dataset and analyst feedback
to compute:
  - Severity accuracy (does the pipeline match expected severity?)
  - Escalation decision accuracy
  - Mean Time to Triage (MTTT) per severity tier
  - Tool call efficiency (tools used vs budget allocated)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

GOLDEN_PATH = Path(__file__).parent / "golden_alerts.json"


def load_golden_cases() -> list[dict[str, Any]]:
    with open(GOLDEN_PATH) as f:
        data = json.load(f)
    return data["alerts"]


def evaluate_verdict(
    verdict: Any,
    expected_severity: str,
    expected_escalation: str,
) -> dict[str, bool]:
    return {
        "severity_correct": verdict.severity.value == expected_severity,
        "escalation_correct": verdict.escalation.value == expected_escalation,
    }


def compute_accuracy(results: list[dict[str, Any]]) -> dict[str, float]:
    if not results:
        return {}
    sev_correct = sum(1 for r in results if r.get("severity_correct", False))
    esc_correct = sum(1 for r in results if r.get("escalation_correct", False))
    n = len(results)
    return {
        "severity_accuracy": round(sev_correct / n, 3),
        "escalation_accuracy": round(esc_correct / n, 3),
        "overall_accuracy": round((sev_correct + esc_correct) / (2 * n), 3),
        "n": n,
    }
