"""
Cost Tracker — records token usage and API call costs per triage run.

In a production SOC environment, this data answers:
  "What does it cost to triage 960 alerts/day?"
  "Which tools are consuming the most budget?"
  "Is the LLM using more tokens on CRITICAL vs LOW alerts?"

Metrics are stored in-memory and exposed via /metrics endpoint.
In production, export to Prometheus/Grafana or a time-series DB.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TriageRunCost:
    alert_id: str
    severity: str
    tools_called: list[str]
    elapsed_ms: int
    timestamp: float = field(default_factory=time.time)

    # Populated if LangSmith callback provides token counts
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0


class CostTracker:
    """In-memory cost and performance tracker for triage pipeline runs."""

    def __init__(self) -> None:
        self._runs: list[TriageRunCost] = []
        self._tool_call_counts: dict[str, int] = defaultdict(int)
        self._tool_latencies_ms: dict[str, list[int]] = defaultdict(list)

    def record_triage(
        self,
        alert_id: str,
        tools_called: list[str],
        elapsed_ms: int,
        severity: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> None:
        # Rough cost estimate for Ollama (self-hosted = $0, but track for cloud comparison)
        cost = (input_tokens * 0.000003 + output_tokens * 0.000015)  # GPT-4o pricing proxy
        run = TriageRunCost(
            alert_id=alert_id,
            severity=severity,
            tools_called=tools_called,
            elapsed_ms=elapsed_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated_cost_usd=cost,
        )
        self._runs.append(run)
        for tool in tools_called:
            self._tool_call_counts[tool] += 1

    def record_tool_latency(self, tool_name: str, latency_ms: int) -> None:
        self._tool_latencies_ms[tool_name].append(latency_ms)

    def get_summary(self) -> dict[str, Any]:
        if not self._runs:
            return {"total_runs": 0}

        latencies = [r.elapsed_ms for r in self._runs]
        by_severity: dict[str, list[int]] = defaultdict(list)
        for r in self._runs:
            by_severity[r.severity].append(r.elapsed_ms)

        tool_avg_latency = {
            tool: int(sum(lats) / len(lats))
            for tool, lats in self._tool_latencies_ms.items()
            if lats
        }

        return {
            "total_runs": len(self._runs),
            "avg_latency_ms": int(sum(latencies) / len(latencies)),
            "p95_latency_ms": sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0,
            "total_estimated_cost_usd": round(sum(r.estimated_cost_usd for r in self._runs), 4),
            "total_input_tokens": sum(r.input_tokens for r in self._runs),
            "total_output_tokens": sum(r.output_tokens for r in self._runs),
            "tool_call_counts": dict(self._tool_call_counts),
            "tool_avg_latency_ms": tool_avg_latency,
            "latency_by_severity": {
                sev: int(sum(lats) / len(lats)) for sev, lats in by_severity.items()
            },
        }

    def get_recent(self, n: int = 20) -> list[dict[str, Any]]:
        return [
            {
                "alert_id": r.alert_id,
                "severity": r.severity,
                "elapsed_ms": r.elapsed_ms,
                "tools_called": r.tools_called,
                "estimated_cost_usd": r.estimated_cost_usd,
            }
            for r in self._runs[-n:]
        ]


_cost_tracker_instance: CostTracker | None = None


def get_cost_tracker() -> CostTracker:
    global _cost_tracker_instance
    if _cost_tracker_instance is None:
        _cost_tracker_instance = CostTracker()
    return _cost_tracker_instance
