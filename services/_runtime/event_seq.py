"""
Event-sequence helper.

Every published triage event carries a monotonic ``event_seq`` per ``alert_id``.
Late-joining DO subscribers read the snapshot's ``last_seq`` and subscribe to
NATS with ``OptStartSeq=last_seq+1``, eliminating the snapshot-then-subscribe
race condition (an event landing between the snapshot read and the subscribe
is now reachable via JetStream's in-order replay).

Concurrency:
- ``next_seq`` and ``current_seq`` are safe to call from multiple workers
  concurrently for the same ``alert_id`` — Redis ``INCR`` is atomic.
- ``next_seq`` advances the counter and returns the new value (use when
  publishing).
- ``current_seq`` reads the counter without advancing (use when reading a
  snapshot).

Redis key layout:
    seq:{alert_id}   ->   integer counter, TTL 24h

The 24h TTL matches the ``ALERTS`` JetStream stream's ``max_age``; if the
stream has dropped a message we don't need its sequence number anymore.
"""

from __future__ import annotations

import structlog

logger = structlog.get_logger(__name__)

_KEY_PREFIX = "seq:"
_DEFAULT_TTL_SEC = 24 * 60 * 60  # 24h, matches ALERTS stream max_age


def _key(alert_id: str) -> str:
    return f"{_KEY_PREFIX}{alert_id}"


class EventSequencer:
    """Per-alert monotonic counter backed by Redis."""

    def __init__(self, redis_url: str, ttl_seconds: int = _DEFAULT_TTL_SEC) -> None:
        self._ttl = ttl_seconds
        self._client = None
        try:
            import redis.asyncio as aioredis

            self._client = aioredis.from_url(redis_url, decode_responses=True)
        except Exception as exc:
            logger.warning("event_seq_init_failed", error=str(exc))

    async def next_seq(self, alert_id: str) -> int:
        """
        Atomically increment and return the next sequence number for the alert.

        Always succeeds. Falls back to a per-process counter if Redis is
        unreachable, but that breaks the cross-worker ordering contract — we
        log a warning so it's visible.
        """
        if self._client is None:
            logger.warning("event_seq_redis_unavailable_fallback", alert_id=alert_id)
            return _local_next(alert_id)
        key = _key(alert_id)
        try:
            seq = await self._client.incr(key)
            # Refresh TTL on every increment so an active alert's counter never
            # expires mid-triage; idle alerts roll off after 24h of silence.
            await self._client.expire(key, self._ttl)
            return int(seq)
        except Exception as exc:
            logger.warning("event_seq_incr_failed", alert_id=alert_id, error=str(exc))
            return _local_next(alert_id)

    async def current_seq(self, alert_id: str) -> int:
        """
        Return the current sequence number without advancing it.

        Used by the DO snapshot read to know where to start the NATS
        subscription. Returns 0 if no events have been published yet.
        """
        if self._client is None:
            return _local_peek(alert_id)
        try:
            raw = await self._client.get(_key(alert_id))
            return int(raw) if raw else 0
        except Exception as exc:
            logger.warning("event_seq_get_failed", alert_id=alert_id, error=str(exc))
            return 0

    async def reset(self, alert_id: str) -> None:
        """Drop the counter (used in tests and for manual cleanup)."""
        if self._client is None:
            _local_reset(alert_id)
            return
        try:
            await self._client.delete(_key(alert_id))
        except Exception as exc:
            logger.warning("event_seq_reset_failed", alert_id=alert_id, error=str(exc))

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()


# ---------------------------------------------------------------------------
# Local fallback (last resort when Redis is unavailable). Breaks cross-worker
# ordering but keeps unit tests and degraded-mode runs functional.
# ---------------------------------------------------------------------------

_local_counters: dict[str, int] = {}


def _local_next(alert_id: str) -> int:
    _local_counters[alert_id] = _local_counters.get(alert_id, 0) + 1
    return _local_counters[alert_id]


def _local_peek(alert_id: str) -> int:
    return _local_counters.get(alert_id, 0)


def _local_reset(alert_id: str) -> None:
    _local_counters.pop(alert_id, None)
