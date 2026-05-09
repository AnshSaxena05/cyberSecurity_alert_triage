"""
Ingest WAL reconciler.

When NATS publish fails (broker down, network blip, JetStream lag), the
ingest endpoint MUST still accept the alert with a 202 — that's the
existing contract today via FastAPI's ``BackgroundTasks``. To preserve
that contract under the new "publish to NATS" architecture, we use a
write-ahead log:

    POST /ingest                         # ingest accepts the alert
        ↓
    Redis: SET pending_alert:{id}        # WAL — durable record of intent
        ↓
    NATS publish (await ack, ~200ms)
        ↓ ok      → DEL pending_alert:{id}  → 202 to client
        ↓ fail    → leave WAL entry         → 202 to client (reconciler picks up)

A background loop (this module) scans ``pending_alert:*`` every few
seconds and retries publishing. Per-key exponential backoff prevents a
single broken alert from monopolising the loop. After ``max_age_seconds``
(default 24h) of failure, the entry is moved to the DLQ stream and a
``stuck_alert`` log line is emitted.

Concurrency:
  * Multiple API processes can run reconcilers concurrently — Redis
    ``SET ... NX`` on the lease key prevents duplicate publishes.
  * Single asyncio task per process; ``start()`` is idempotent.

Redis key layout:
    pending_alert:{alert_id}    → JSON payload, EX = max_age_seconds
    pending_alert_lease:{alert_id} → owner-id, EX = lease_seconds
    pending_alert_attempts:{alert_id} → integer, EX = max_age_seconds
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

_KEY_PENDING = "pending_alert:"
_KEY_LEASE = "pending_alert_lease:"
_KEY_ATTEMPTS = "pending_alert_attempts:"

# Backoff schedule by attempt number (0-indexed). After exhausting, the
# entry is moved to DLQ.
_BACKOFF_SECONDS = (5, 30, 300, 1800, 3600, 3600 * 4, 3600 * 8)


def _pending_key(alert_id: str) -> str:
    return f"{_KEY_PENDING}{alert_id}"


def _lease_key(alert_id: str) -> str:
    return f"{_KEY_LEASE}{alert_id}"


def _attempts_key(alert_id: str) -> str:
    return f"{_KEY_ATTEMPTS}{alert_id}"


class IngestReconciler:
    """
    Background loop that drains ``pending_alert:*`` from Redis to NATS.

    Construct with the same NatsBroker and a Redis URL; call ``start()``
    on FastAPI startup and ``stop()`` on shutdown. The reconciler is the
    only path that retries failed publishes — the request handler does
    not retry inline (latency budget).
    """

    def __init__(
        self,
        *,
        broker,                                                    # NatsBroker
        redis_url: str,
        publish_subject_for: callable,                             # (payload_dict) -> subject
        max_age_seconds: int = 24 * 60 * 60,
        scan_interval_seconds: float = 5.0,
        lease_seconds: int = 30,
        owner_id: str | None = None,
        dlq_publisher=None,   # async fn(alert_id, payload, reason)
    ) -> None:
        self._broker = broker
        self._redis_url = redis_url
        self._max_age = max_age_seconds
        self._scan_interval = scan_interval_seconds
        self._lease = lease_seconds
        self._owner = owner_id or secrets.token_hex(8)
        self._publish_subject_for = publish_subject_for
        self._dlq = dlq_publisher
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._client = None
        try:
            import redis.asyncio as aioredis

            self._client = aioredis.from_url(redis_url, decode_responses=True)
        except Exception as exc:
            logger.warning("ingest_reconciler_redis_init_failed", error=str(exc))

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._loop())
        logger.info("ingest_reconciler_started", owner=self._owner)

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except TimeoutError:
                self._task.cancel()
        if self._client is not None:
            await self._client.aclose()
        logger.info("ingest_reconciler_stopped", owner=self._owner)

    # -----------------------------------------------------------------
    # WAL helpers — called by the ingest path
    # -----------------------------------------------------------------

    async def write_ahead(self, alert_id: str, payload: dict[str, Any]) -> bool:
        """
        Persist the alert to the WAL before attempting NATS publish.
        Returns True if WAL is written (or Redis is down — we degrade open).
        """
        if self._client is None:
            return True   # no Redis → degrade-open: ingest still accepts
        try:
            await self._client.setex(
                _pending_key(alert_id),
                self._max_age,
                json.dumps(payload),
            )
            return True
        except Exception as exc:
            logger.warning("ingest_wal_write_failed", alert_id=alert_id, error=str(exc))
            return True   # still accept ingest; reconciler is best-effort

    async def mark_published(self, alert_id: str) -> None:
        """Called by the ingest path after a successful inline publish."""
        if self._client is None:
            return
        try:
            await self._client.delete(
                _pending_key(alert_id),
                _lease_key(alert_id),
                _attempts_key(alert_id),
            )
        except Exception as exc:
            logger.warning("ingest_wal_mark_failed", alert_id=alert_id, error=str(exc))

    # -----------------------------------------------------------------
    # Loop body — exposed as ``run_once`` so tests don't need to wait.
    # -----------------------------------------------------------------

    async def run_once(self) -> int:
        """Process at most one batch. Returns the number of pending entries scanned."""
        if self._client is None:
            return 0
        scanned = 0
        async for key in self._client.scan_iter(match=f"{_KEY_PENDING}*", count=100):
            scanned += 1
            alert_id = key[len(_KEY_PENDING):]
            if not await self._acquire_lease(alert_id):
                continue
            try:
                await self._process_one(alert_id)
            finally:
                await self._release_lease(alert_id)
        return scanned

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self.run_once()
            except Exception as exc:
                logger.warning("ingest_reconciler_loop_error", error=str(exc))
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._scan_interval)
            except TimeoutError:
                continue

    # -----------------------------------------------------------------
    # Process one pending alert
    # -----------------------------------------------------------------

    async def _process_one(self, alert_id: str) -> None:
        if self._client is None:
            return
        raw = await self._client.get(_pending_key(alert_id))
        if not raw:
            return  # someone else cleaned it up
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("ingest_wal_corrupt", alert_id=alert_id, error=str(exc))
            await self._client.delete(_pending_key(alert_id))
            return

        attempts = await self._increment_attempts(alert_id)

        # Backoff — only retry if enough time has passed since the last try.
        # We approximate the "last try" as ``ttl - (max_age - (attempts-1)*scan_interval)``;
        # a simpler model: just attempt every scan tick but with ratcheting jitter.
        wait_idx = min(attempts - 1, len(_BACKOFF_SECONDS) - 1)
        # Skip work if we've attempted too recently. Tracked separately so
        # multiple reconciler processes don't pile on.
        next_after_key = f"{_KEY_ATTEMPTS}{alert_id}:next"
        next_after = await self._client.get(next_after_key)
        if next_after and time.time() < float(next_after):
            return

        subject = self._publish_subject_for(payload)
        ok = await self._broker.publish(
            subject,
            json.dumps(payload).encode(),
            msg_id=alert_id,
            await_ack=True,
        )
        if ok:
            logger.info(
                "ingest_wal_published",
                alert_id=alert_id,
                attempts=attempts,
                subject=subject,
            )
            await self.mark_published(alert_id)
            return

        # Schedule the next retry.
        delay = _BACKOFF_SECONDS[wait_idx]
        await self._client.setex(next_after_key, self._max_age, str(time.time() + delay))
        logger.warning(
            "ingest_wal_publish_failed",
            alert_id=alert_id,
            attempts=attempts,
            next_retry_in=delay,
        )

        if attempts >= len(_BACKOFF_SECONDS):
            await self._move_to_dlq(alert_id, payload, reason="max_retries_exhausted")

    # -----------------------------------------------------------------
    # Lease — prevents two reconcilers double-publishing the same alert
    # -----------------------------------------------------------------

    async def _acquire_lease(self, alert_id: str) -> bool:
        if self._client is None:
            return False
        ok = await self._client.set(
            _lease_key(alert_id),
            self._owner,
            nx=True,
            ex=self._lease,
        )
        return bool(ok)

    async def _release_lease(self, alert_id: str) -> None:
        if self._client is None:
            return
        # Use a tiny Lua script so we only delete the lease if we still own it.
        try:
            await self._client.eval(
                """
                if redis.call('GET', KEYS[1]) == ARGV[1] then
                  return redis.call('DEL', KEYS[1])
                else
                  return 0
                end
                """,
                1,
                _lease_key(alert_id),
                self._owner,
            )
        except Exception as exc:
            logger.warning("ingest_lease_release_failed", alert_id=alert_id, error=str(exc))

    async def _increment_attempts(self, alert_id: str) -> int:
        if self._client is None:
            return 1
        try:
            n = await self._client.incr(_attempts_key(alert_id))
            await self._client.expire(_attempts_key(alert_id), self._max_age)
            return int(n)
        except Exception as exc:
            logger.warning("ingest_attempts_failed", alert_id=alert_id, error=str(exc))
            return 1

    async def _move_to_dlq(self, alert_id: str, payload: dict[str, Any], reason: str) -> None:
        logger.warning("ingest_wal_to_dlq", alert_id=alert_id, reason=reason)
        if self._dlq is not None:
            try:
                await self._dlq(alert_id, payload, reason)
            except Exception as exc:
                logger.warning("ingest_dlq_publish_failed", alert_id=alert_id, error=str(exc))
        if self._client is not None:
            try:
                await self._client.delete(
                    _pending_key(alert_id),
                    _attempts_key(alert_id),
                    f"{_KEY_ATTEMPTS}{alert_id}:next",
                )
            except Exception as exc:
                logger.warning("ingest_wal_cleanup_failed", alert_id=alert_id, error=str(exc))


def reconciler_from_env(broker, publish_subject_for) -> IngestReconciler:
    """Convenience factory for FastAPI startup hooks."""
    return IngestReconciler(
        broker=broker,
        redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        publish_subject_for=publish_subject_for,
    )
