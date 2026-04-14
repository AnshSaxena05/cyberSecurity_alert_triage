"""
Analyst Feedback — captures analyst overrides and thumbs up/down signals.

This data is the foundation for future fine-tuning of the routing table
and prompt improvements. Even without ML infrastructure, tracking disagreements
reveals systematic biases in the model's verdict generation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class FeedbackRecord:
    alert_id: str
    original_verdict: str          # escalation decision from pipeline
    analyst_decision: str          # what the analyst actually decided
    agree: bool
    comment: str = ""
    analyst_id: str = "anonymous"
    timestamp: float = field(default_factory=time.time)


class FeedbackStore:
    def __init__(self) -> None:
        self._records: list[FeedbackRecord] = []

    def record(
        self,
        alert_id: str,
        original_verdict: str,
        analyst_decision: str,
        comment: str = "",
        analyst_id: str = "anonymous",
    ) -> None:
        agree = original_verdict.upper() == analyst_decision.upper()
        self._records.append(
            FeedbackRecord(
                alert_id=alert_id,
                original_verdict=original_verdict,
                analyst_decision=analyst_decision,
                agree=agree,
                comment=comment,
                analyst_id=analyst_id,
            )
        )

    def agreement_rate(self) -> float:
        if not self._records:
            return 0.0
        return sum(1 for r in self._records if r.agree) / len(self._records)

    def disagreements(self) -> list[dict[str, Any]]:
        return [
            {
                "alert_id": r.alert_id,
                "pipeline_said": r.original_verdict,
                "analyst_said": r.analyst_decision,
                "comment": r.comment,
            }
            for r in self._records
            if not r.agree
        ]

    def summary(self) -> dict[str, Any]:
        total = len(self._records)
        if not total:
            return {"total_feedback": 0}
        agreement = self.agreement_rate()
        # Which decisions does the pipeline get wrong most?
        from collections import Counter
        fp_cases = Counter(
            r.original_verdict for r in self._records
            if not r.agree and r.analyst_decision == "FALSE_POSITIVE"
        )
        return {
            "total_feedback": total,
            "agreement_rate": round(agreement, 3),
            "false_positive_overcalls": dict(fp_cases),
            "disagreements_count": total - int(agreement * total),
        }


_feedback_store_instance: FeedbackStore | None = None


def get_feedback_store() -> FeedbackStore:
    global _feedback_store_instance
    if _feedback_store_instance is None:
        _feedback_store_instance = FeedbackStore()
    return _feedback_store_instance
