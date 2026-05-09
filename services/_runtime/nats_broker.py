"""
NATS JetStream client and subject naming.

Mirrors the Redis client pattern in services/context_cache.py. Single
``NatsBroker`` instance per process; lazily connects; gracefully degrades
to a no-op publisher if NATS is unreachable (the ingest WAL handles
durability separately).

Subject scheme (versioned; see plan section B):

    alerts.v1.{tenant_id}.{source}.{alert_id}
    triage.events.v1.{tenant_id}.{alert_id}.{phase}
    triage.cancel.v1.{tenant_id}.{alert_id}
    auth.revocations.v1.{tenant_id}.{user_id}
    feedback.v1.{tenant_id}.{alert_id}
    dlq.v1.{tenant_id}.{origin_stream}.{alert_id}

Streams (5 total — capacity is independent of tenant count):

    ALERTS         WorkQueue   max_age=24h
    TRIAGE_EVENTS  Interest    max_age=10m
    CONTROL        Interest    max_age=5m
    FEEDBACK       Limits      max_age=90d
    DLQ            Limits      max_age=7d

Concurrency:
  - One NATS connection per process; thread-safe per nats-py docs.
  - Publish is awaitable; ingest paths await ack, event paths fire-and-forget.
  - Pull consumer methods return iterables; each consumer should run in its
    own asyncio task.

This module is a SKELETON. The full publisher/consumer plumbing lands in
week 2 of the plan; this file establishes the interface so other modules
can import from a stable location.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

SCHEMA_VERSION_TAG = "v1"


# ---------------------------------------------------------------------------
# Subject constructors. Centralise so a future v2 bump is one diff.
# ---------------------------------------------------------------------------


def subj_alert(tenant_id: str, source: str, alert_id: str) -> str:
    return f"alerts.{SCHEMA_VERSION_TAG}.{tenant_id}.{source}.{alert_id}"


def subj_triage_event(tenant_id: str, alert_id: str, phase: str) -> str:
    return f"triage.events.{SCHEMA_VERSION_TAG}.{tenant_id}.{alert_id}.{phase}"


def subj_triage_cancel(tenant_id: str, alert_id: str) -> str:
    return f"triage.cancel.{SCHEMA_VERSION_TAG}.{tenant_id}.{alert_id}"


def subj_auth_revocation(tenant_id: str, user_id: str) -> str:
    return f"auth.revocations.{SCHEMA_VERSION_TAG}.{tenant_id}.{user_id}"


def subj_feedback(tenant_id: str, alert_id: str) -> str:
    return f"feedback.{SCHEMA_VERSION_TAG}.{tenant_id}.{alert_id}"


def subj_dlq(tenant_id: str, origin_stream: str, alert_id: str) -> str:
    return f"dlq.{SCHEMA_VERSION_TAG}.{tenant_id}.{origin_stream}.{alert_id}"


# ---------------------------------------------------------------------------
# Stream definitions (used by the bootstrap script that creates streams in
# a fresh NATS cluster). Not invoked at runtime by services.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StreamSpec:
    name: str
    subjects: tuple[str, ...]
    retention: str           # "limits" | "interest" | "workqueue"
    max_age_seconds: int


STREAM_SPECS: tuple[StreamSpec, ...] = (
    StreamSpec(
        name="ALERTS",
        subjects=(f"alerts.{SCHEMA_VERSION_TAG}.>",),
        retention="workqueue",
        max_age_seconds=24 * 60 * 60,
    ),
    StreamSpec(
        name="TRIAGE_EVENTS",
        subjects=(f"triage.events.{SCHEMA_VERSION_TAG}.>",),
        retention="interest",
        max_age_seconds=10 * 60,
    ),
    StreamSpec(
        name="CONTROL",
        subjects=(
            f"triage.cancel.{SCHEMA_VERSION_TAG}.>",
            f"auth.revocations.{SCHEMA_VERSION_TAG}.>",
        ),
        retention="interest",
        max_age_seconds=5 * 60,
    ),
    StreamSpec(
        name="FEEDBACK",
        subjects=(f"feedback.{SCHEMA_VERSION_TAG}.>",),
        retention="limits",
        max_age_seconds=90 * 24 * 60 * 60,
    ),
    StreamSpec(
        name="DLQ",
        subjects=(f"dlq.{SCHEMA_VERSION_TAG}.>",),
        retention="limits",
        max_age_seconds=7 * 24 * 60 * 60,
    ),
)


# ---------------------------------------------------------------------------
# Broker. Skeleton in this commit; publisher/consumer methods land in week 2.
# ---------------------------------------------------------------------------


class NatsBroker:
    """JetStream-aware NATS client. One per process."""

    def __init__(
        self,
        servers: str,
        creds_path: str | None = None,
        name: str = "soc-triage",
    ) -> None:
        self._servers = servers
        self._creds_path = creds_path
        self._name = name
        self._nc = None        # type: Any
        self._js = None        # type: Any
        self._connected = False

    async def connect(self) -> None:
        """Lazily connect. Idempotent."""
        if self._connected:
            return
        try:
            import nats

            opts: dict[str, Any] = {"servers": self._servers, "name": self._name}
            if self._creds_path:
                opts["user_credentials"] = self._creds_path
            self._nc = await nats.connect(**opts)
            self._js = self._nc.jetstream()
            self._connected = True
            logger.info("nats_connected", servers=self._servers)
        except Exception as exc:
            logger.warning("nats_connect_failed", error=str(exc), servers=self._servers)
            # Stay in disconnected mode; publish becomes no-op until reconnected.
            self._connected = False

    async def publish(
        self,
        subject: str,
        payload: bytes,
        *,
        msg_id: str | None = None,
        headers: dict[str, str] | None = None,
        await_ack: bool = False,
    ) -> bool:
        """
        Publish a message. Returns True on success, False if NATS is
        unreachable. ``msg_id`` is set as the JetStream Nats-Msg-Id header
        for dedup on redelivery (use the alert_id for idempotency).

        ``await_ack=True`` for ingest paths (durability needed); False for
        ephemeral phase/token events.
        """
        if not self._connected:
            await self.connect()
        if not self._connected or self._js is None:
            return False
        all_headers: dict[str, str] = {}
        if msg_id:
            all_headers["Nats-Msg-Id"] = msg_id
        if headers:
            all_headers.update(headers)
        try:
            if await_ack:
                await self._js.publish(subject, payload, headers=all_headers or None)
            else:
                # Fire-and-forget on the core NATS connection (faster for ephemeral).
                # Note: TRIAGE_EVENTS subjects are bound to a JetStream stream,
                # so publishing to NATS core still routes through the stream.
                await self._nc.publish(subject, payload, headers=all_headers or None)
            return True
        except Exception as exc:
            logger.warning(
                "nats_publish_failed", subject=subject, msg_id=msg_id, error=str(exc)
            )
            return False

    async def pull_subscribe(
        self,
        subject_filter: str,
        *,
        durable: str,
        ack_wait_seconds: int = 60,
        max_deliver: int = 5,
    ) -> Any:
        """
        Build a JetStream durable pull consumer for ``subject_filter``.

        Returns the underlying ``PullSubscription`` so the caller can do
        ``msgs = await sub.fetch(batch=N, timeout=...)``. Returns ``None``
        if NATS isn't connected (caller should fail soft and retry).
        """
        if not self._connected:
            await self.connect()
        if not self._connected or self._js is None:
            return None
        try:
            from nats.js.api import ConsumerConfig

            sub = await self._js.pull_subscribe(
                subject=subject_filter,
                durable=durable,
                config=ConsumerConfig(
                    ack_wait=ack_wait_seconds,
                    max_deliver=max_deliver,
                ),
            )
            return sub
        except Exception as exc:
            logger.warning(
                "nats_pull_subscribe_failed",
                subject_filter=subject_filter,
                durable=durable,
                error=str(exc),
            )
            return None

    async def close(self) -> None:
        if self._nc is not None:
            try:
                await self._nc.drain()
            except Exception as exc:
                logger.warning("nats_drain_failed", error=str(exc))
        self._connected = False
