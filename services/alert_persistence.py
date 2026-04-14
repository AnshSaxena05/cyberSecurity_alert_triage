"""
Optional Redis-backed persistence for normalised alerts, verdicts, and job status.

Falls back to in-memory dicts when disabled or Redis is unavailable.
"""

from __future__ import annotations

import json
from typing import Any, Literal

import structlog

from app.models import NormalizedAlert, TriageVerdict

logger = structlog.get_logger(__name__)

JobStatus = Literal["queued", "running", "complete", "failed"]

KEY_ALERT = "soc:alert:"
KEY_VERDICT = "soc:verdict:"
KEY_JOB = "soc:job:"


class AlertPersistence:
    """Dual-mode store: Redis when enabled, else process-local dicts."""

    def __init__(self, redis_url: str, enabled: bool) -> None:
        self._enabled = enabled
        self._redis: Any = None
        self._mem_alerts: dict[str, NormalizedAlert] = {}
        self._mem_verdicts: dict[str, TriageVerdict] = {}
        self._mem_jobs: dict[str, dict[str, Any]] = {}

        if enabled:
            try:
                import redis.asyncio as aioredis

                self._redis = aioredis.from_url(redis_url, decode_responses=True)
                logger.info("alert_persistence_redis_enabled")
            except Exception as exc:
                logger.warning("alert_persistence_redis_failed", error=str(exc), fallback="memory")
                self._enabled = False
                self._redis = None

    async def close(self) -> None:
        if self._redis:
            await self._redis.aclose()

    async def put_alert(self, alert: NormalizedAlert) -> None:
        if self._redis:
            await self._redis.set(
                f"{KEY_ALERT}{alert.alert_id}",
                alert.model_dump_json(),
            )
            return
        self._mem_alerts[alert.alert_id] = alert

    async def get_alert(self, alert_id: str) -> NormalizedAlert | None:
        if self._redis:
            raw = await self._redis.get(f"{KEY_ALERT}{alert_id}")
            if not raw:
                return None
            return NormalizedAlert.model_validate_json(raw)
        return self._mem_alerts.get(alert_id)

    async def put_verdict(self, alert_id: str, verdict: TriageVerdict) -> None:
        if self._redis:
            await self._redis.set(
                f"{KEY_VERDICT}{alert_id}",
                verdict.model_dump_json(),
            )
            return
        self._mem_verdicts[alert_id] = verdict

    async def get_verdict(self, alert_id: str) -> TriageVerdict | None:
        if self._redis:
            raw = await self._redis.get(f"{KEY_VERDICT}{alert_id}")
            if not raw:
                return None
            return TriageVerdict.model_validate_json(raw)
        return self._mem_verdicts.get(alert_id)

    async def set_job(self, alert_id: str, status: JobStatus, error: str | None = None) -> None:
        rec = {"status": status, "error": error}
        if self._redis:
            await self._redis.set(
                f"{KEY_JOB}{alert_id}",
                json.dumps(rec),
            )
            return
        self._mem_jobs[alert_id] = rec

    async def get_job(self, alert_id: str) -> dict[str, Any] | None:
        if self._redis:
            raw = await self._redis.get(f"{KEY_JOB}{alert_id}")
            if not raw:
                return None
            return json.loads(raw)
        return self._mem_jobs.get(alert_id)

    async def store_sizes(self) -> dict[str, Any]:
        """Approximate in-memory counts (Redis mode returns -1 for unknown totals)."""
        if self._redis:
            return {"verdict_count": -1, "alert_count": -1, "backend": "redis"}
        return {
            "verdict_count": len(self._mem_verdicts),
            "alert_count": len(self._mem_alerts),
            "backend": "memory",
        }


_persistence: AlertPersistence | None = None


def get_alert_persistence() -> AlertPersistence:
    global _persistence
    if _persistence is None:
        from app.config import get_settings

        s = get_settings()
        use_redis = bool(s.verdict_persistence_enabled and s.redis_url)
        _persistence = AlertPersistence(redis_url=s.redis_url, enabled=use_redis)
    return _persistence


def reset_alert_persistence_for_tests() -> None:
    global _persistence
    _persistence = None
