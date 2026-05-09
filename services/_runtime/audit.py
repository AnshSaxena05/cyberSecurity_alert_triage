"""
Raw-payload retention and coercion-trace recording.

Driven by the audit gap called out in plan section A10. When a payload
goes through the LLM-coercion path of ``/ingest/auto`` (because the
schema didn't match a known parser), the resulting ``NormalizedAlert``
is the LLM's interpretation. A regulator (NIS2 / SOC 2 / DORA) asking
"show me the original payload exactly as received and what your system
did with it" must be answerable from this module.

What we persist (per alert):

  * ``raw_payload:{alert_id}`` — the bytewise original payload, JSON-encoded.
    Persisted for *every* alert, not just coerced ones. TTL configurable
    per tenant (default 30 days; regulated tenants 90/180/365).
  * ``coercion_traces:{trace_id}`` — only when the LLM coercion path
    fired. Records ``{prompt, model, response, latency_ms, cost_usd}``.
    Retained for the same TTL as the raw payload.

Out of scope here (planned for week 6):

  * S3 mirror with object-lock for legal-hold tenants.
  * Weekly hash-chained manifest dump for tamper-evidence.
  * ``GET /audit/{alert_id}`` endpoint surfacing the bundle behind an
    auditor RBAC role.

Concurrency:
  * All methods are async and Redis-backed.
  * Safe to call from any process; per-key writes don't conflict.
  * ``record_raw_payload`` is fire-and-forget — failures are logged but
    do not propagate, since the audit trail is best-effort and must
    never block ingest.
"""

from __future__ import annotations

import json
import os
import secrets
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

_KEY_RAW = "raw_payload:"
_KEY_COERCION = "coercion_traces:"
_DEFAULT_TTL_SEC = 30 * 24 * 60 * 60   # 30 days


def _raw_key(alert_id: str) -> str:
    return f"{_KEY_RAW}{alert_id}"


def _coercion_key(trace_id: str) -> str:
    return f"{_KEY_COERCION}{trace_id}"


class AuditStore:
    """Per-tenant audit-record persistence."""

    def __init__(
        self,
        redis_url: str,
        *,
        default_ttl_seconds: int = _DEFAULT_TTL_SEC,
        tenant_ttl_overrides: dict[str, int] | None = None,
    ) -> None:
        self._default_ttl = default_ttl_seconds
        self._overrides = dict(tenant_ttl_overrides or {})
        self._client = None
        try:
            import redis.asyncio as aioredis

            self._client = aioredis.from_url(redis_url, decode_responses=True)
        except Exception as exc:
            logger.warning("audit_init_failed", error=str(exc))

    # -----------------------------------------------------------------
    # Raw payload — every alert
    # -----------------------------------------------------------------

    async def record_raw_payload(
        self,
        alert_id: str,
        tenant_id: str | None,
        payload: dict[str, Any],
    ) -> None:
        if self._client is None:
            return
        ttl = self._ttl_for(tenant_id)
        try:
            body = json.dumps(payload, default=str)
            await self._client.setex(_raw_key(alert_id), ttl, body)
        except Exception as exc:
            logger.warning("audit_raw_write_failed", alert_id=alert_id, error=str(exc))

    async def get_raw_payload(self, alert_id: str) -> dict[str, Any] | None:
        if self._client is None:
            return None
        try:
            v = await self._client.get(_raw_key(alert_id))
            return json.loads(v) if v else None
        except Exception as exc:
            logger.warning("audit_raw_read_failed", alert_id=alert_id, error=str(exc))
            return None

    # -----------------------------------------------------------------
    # Coercion trace — only when /ingest/auto LLM-coerced an unknown shape
    # -----------------------------------------------------------------

    async def record_coercion(
        self,
        *,
        alert_id: str,
        tenant_id: str | None,
        prompt: str,
        model: str,
        response: dict[str, Any] | str,
        latency_ms: int,
        cost_usd: float | None = None,
    ) -> str:
        """
        Persist the LLM coercion trace and return the new ``trace_id``.

        Caller should set ``NormalizedAlert.coercion_trace_id`` to the
        returned value so downstream audit lookups can correlate.
        """
        trace_id = secrets.token_urlsafe(12)
        if self._client is None:
            return trace_id
        ttl = self._ttl_for(tenant_id)
        record = {
            "alert_id": alert_id,
            "tenant_id": tenant_id,
            "prompt": prompt,
            "model": model,
            "response": response,
            "latency_ms": latency_ms,
            "cost_usd": cost_usd,
        }
        try:
            await self._client.setex(_coercion_key(trace_id), ttl, json.dumps(record, default=str))
        except Exception as exc:
            logger.warning("audit_coercion_write_failed", alert_id=alert_id, error=str(exc))
        return trace_id

    async def get_coercion(self, trace_id: str) -> dict[str, Any] | None:
        if self._client is None:
            return None
        try:
            v = await self._client.get(_coercion_key(trace_id))
            return json.loads(v) if v else None
        except Exception as exc:
            logger.warning("audit_coercion_read_failed", trace_id=trace_id, error=str(exc))
            return None

    # -----------------------------------------------------------------
    # Bundle assembly — used by the future /audit/{alert_id} endpoint
    # -----------------------------------------------------------------

    async def get_bundle(
        self,
        alert_id: str,
        coercion_trace_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Return everything we have on this alert for audit review.

        The caller is expected to merge the verdict, the analyst-feedback
        record, and the LangGraph checkpoint history into the surfaced
        view; those live in their own stores.
        """
        bundle: dict[str, Any] = {
            "alert_id": alert_id,
            "raw_payload": await self.get_raw_payload(alert_id),
        }
        if coercion_trace_id:
            bundle["coercion"] = await self.get_coercion(coercion_trace_id)
        return bundle

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------

    def _ttl_for(self, tenant_id: str | None) -> int:
        if tenant_id and tenant_id in self._overrides:
            return self._overrides[tenant_id]
        return self._default_ttl

    def set_tenant_override(self, tenant_id: str, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self._overrides[tenant_id] = ttl_seconds

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()


def audit_store_from_env() -> AuditStore:
    """Convenience factory."""
    return AuditStore(
        redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
    )
