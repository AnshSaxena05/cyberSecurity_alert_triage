"""
Cancellation flag with grace-window debounce.

When a browser closes a WebSocket without a verdict yet, the gateway/DO
publishes ``triage.cancel.v1.{tenant}.{alert_id}``. A worker listening to
that subject sets a Redis flag ``cancelled:{alert_id}`` after a short
debounce (default 5s) so a quick tab-reopen doesn't kill an in-flight
investigation.

The triage worker reads ``is_cancelled(alert_id)`` at every LLM-call
boundary in the LangGraph nodes (`agent_think`, `execute_tool`). On a hit
the worker writes ``status="cancelled"`` to the verdict, ACKs the NATS
message, and exits the graph cleanly.

Concurrency:
- ``request_cancel`` is idempotent. Calling it twice within the grace
  window resets the timer (no double-fire).
- ``revoke_cancel`` aborts a pending cancellation if the user reopens the
  tab quickly. It does not undo a cancel that has already fired.
- ``is_cancelled`` is a fast Redis ``GET``; safe to poll every loop iter.

Redis key layout:
    cancel_pending:{alert_id}    ->    "1", EX = grace_seconds
    cancelled:{alert_id}          ->    "1", EX = 24h (matches ALERTS max_age)
"""

from __future__ import annotations

import asyncio

import structlog

logger = structlog.get_logger(__name__)

_KEY_PENDING_PREFIX = "cancel_pending:"
_KEY_CANCELLED_PREFIX = "cancelled:"
_DEFAULT_GRACE_SEC = 5
_CANCELLED_TTL_SEC = 24 * 60 * 60


def _pending_key(alert_id: str) -> str:
    return f"{_KEY_PENDING_PREFIX}{alert_id}"


def _cancelled_key(alert_id: str) -> str:
    return f"{_KEY_CANCELLED_PREFIX}{alert_id}"


class CancelRegistry:
    """Per-alert cancellation flag with grace-window debouncing."""

    def __init__(
        self,
        redis_url: str,
        grace_seconds: int = _DEFAULT_GRACE_SEC,
    ) -> None:
        self._grace = grace_seconds
        self._client = None
        # Tracks asyncio tasks for in-flight grace timers. Keyed by alert_id;
        # cancelled if the user reopens the tab and we want to abort the cancel.
        self._timers: dict[str, asyncio.Task] = {}
        try:
            import redis.asyncio as aioredis

            self._client = aioredis.from_url(redis_url, decode_responses=True)
        except Exception as exc:
            logger.warning("cancel_init_failed", error=str(exc))

    async def is_cancelled(self, alert_id: str) -> bool:
        """Fast read-path check. Safe to poll at every LLM-call boundary."""
        if self._client is None:
            return False
        try:
            v = await self._client.get(_cancelled_key(alert_id))
            return v == "1"
        except Exception as exc:
            logger.warning("cancel_check_failed", alert_id=alert_id, error=str(exc))
            return False

    async def request_cancel(self, alert_id: str) -> None:
        """
        Schedule a cancellation. After ``grace_seconds`` of no ``revoke_cancel``,
        the cancel takes effect. Idempotent: calling twice resets the timer.
        """
        if self._client is None:
            return

        # If a timer is already pending, restart it (debounce).
        existing = self._timers.pop(alert_id, None)
        if existing is not None and not existing.done():
            existing.cancel()

        try:
            # Buffer the TTL so the pending flag outlives the grace timer.
            # Without this, the SETEX expiry races the asyncio.sleep wake-up
            # and the fire path can read a missing key the moment its timer
            # fires, treating an unrevoked cancel as already-revoked.
            await self._client.setex(_pending_key(alert_id), self._grace + 5, "1")
        except Exception as exc:
            logger.warning("cancel_pending_failed", alert_id=alert_id, error=str(exc))
            return

        task = asyncio.create_task(self._fire_after_grace(alert_id))
        self._timers[alert_id] = task

    async def revoke_cancel(self, alert_id: str) -> None:
        """User reopened the tab in time; abort the pending cancel."""
        existing = self._timers.pop(alert_id, None)
        if existing is not None and not existing.done():
            existing.cancel()
        if self._client is None:
            return
        try:
            await self._client.delete(_pending_key(alert_id))
        except Exception as exc:
            logger.warning("cancel_revoke_failed", alert_id=alert_id, error=str(exc))

    async def _fire_after_grace(self, alert_id: str) -> None:
        try:
            await asyncio.sleep(self._grace)
        except asyncio.CancelledError:
            return
        if self._client is None:
            return
        # Double-check the pending flag is still set; if revoke_cancel fired
        # between the timer scheduling and now, the key will be gone.
        try:
            still_pending = await self._client.get(_pending_key(alert_id))
            if still_pending != "1":
                return
            await self._client.setex(_cancelled_key(alert_id), _CANCELLED_TTL_SEC, "1")
            await self._client.delete(_pending_key(alert_id))
            logger.info("cancel_fired", alert_id=alert_id)
        except Exception as exc:
            logger.warning("cancel_fire_failed", alert_id=alert_id, error=str(exc))
        finally:
            self._timers.pop(alert_id, None)

    async def close(self) -> None:
        for t in list(self._timers.values()):
            if not t.done():
                t.cancel()
        self._timers.clear()
        if self._client is not None:
            await self._client.aclose()
