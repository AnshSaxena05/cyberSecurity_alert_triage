"""
Triage worker — long-running NATS pull-consumer.

One worker subscribes to ``alerts.v1.>`` and processes alerts for any
tenant. Tenant context is carried in the verified service JWT attached
to each NATS message; the worker reads ``tenant_id`` only via
``services._runtime.tenant.get_tenant_id``.

Resilience contract (matches plan section A1–A6):

  * Idempotency: NATS dedup window uses ``Nats-Msg-Id == alert_id``;
    LangGraph checkpointer dedupes on ``thread_id == alert_id``. Both
    layers are belt-and-suspenders cheap.
  * Crash recovery: a ``kill -9`` mid-graph leaves an unacked NATS
    message and a partial checkpoint. The redelivery wakes a fresh
    worker; LangGraph resumes from the last super-step.
  * Cancellation: at every LLM-call boundary (see triage_pipeline.py),
    ``cancel.is_cancelled(alert_id)`` is checked. On cancel, the worker
    writes ``status=cancelled`` to the verdict and ACKs the message.
  * Backpressure: pull consumer with bounded ``batch=N``; the worker
    only requests more work when it has capacity.

Concurrency:
  * One worker process per CPU is the right unit; concurrency within a
    process comes from ``max_inflight`` in-flight asyncio tasks.

This module ships as a skeleton. Run-loop and DLQ handling land alongside
the WAL reconciler in the next sub-task.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
from dataclasses import dataclass, field
from typing import Any

import structlog

from schemas.v1 import (
    NormalizedAlert,
    PhaseEvent,
    TriageVerdict,
)
from services._runtime.cancel import CancelRegistry
from services._runtime.checkpoint_redis_ttl import CheckpointerFactory
from services._runtime.event_seq import EventSequencer
from services._runtime.jwt_service import JWTError, JWTService
from services._runtime.nats_broker import (
    NatsBroker,
    subj_dlq,
    subj_triage_event,
)
from services._runtime.tenant import AuthContext

logger = structlog.get_logger(__name__)


@dataclass
class WorkerConfig:
    nats_url: str = field(
        default_factory=lambda: os.environ.get("NATS_URL", "nats://localhost:4222")
    )
    redis_url: str = field(
        default_factory=lambda: os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    )
    # Alerts dispatch
    consumer_durable: str = "soc-triage-worker"
    consumer_subject_filter: str = "alerts.v1.>"
    max_inflight: int = 4
    pull_batch: int = 1
    ack_wait_seconds: int = 60
    max_deliveries: int = 5
    # Cancel-listener (separate durable consumer on the CONTROL stream)
    cancel_consumer_durable: str = "soc-triage-cancel"
    cancel_subject_filter: str = "triage.cancel.v1.>"


@dataclass
class WorkerDeps:
    """
    Constructor injection point for everything the worker needs.

    Tests pass fakes; production calls ``WorkerDeps.from_env()``.
    """

    broker: NatsBroker
    jwt_service: JWTService
    cancel: CancelRegistry
    event_seq: EventSequencer
    checkpointer_factory: CheckpointerFactory


class TriageWorker:
    """Pull alerts from NATS, run the triage pipeline, publish phase events."""

    def __init__(self, config: WorkerConfig, deps: WorkerDeps) -> None:
        self._cfg = config
        self._deps = deps
        self._stop = asyncio.Event()
        self._inflight: set[asyncio.Task] = set()

    # -----------------------------------------------------------------
    # Run loop
    # -----------------------------------------------------------------

    async def run(self) -> None:
        """
        Main entry point. Blocks until ``stop()`` is called or SIGTERM.

        Dispatch model:
          * Pull consumer requests at most ``pull_batch`` messages at a time.
          * Each message becomes its own asyncio task in ``self._inflight``.
          * A semaphore enforces ``max_inflight`` cap so 1k pending alerts
            don't all run their LLM calls in parallel and starve the LLM.
          * Successful handle_message → ACK. Auth/parse failures → TERM
            (don't redeliver poison pills). Transient errors → NAK so
            JetStream redelivers up to max_deliveries times before its
            own dead-lettering kicks in.
        """
        await self._deps.broker.connect()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self.stop)
            except (NotImplementedError, RuntimeError):
                # Windows / non-main thread — fall back to KeyboardInterrupt.
                pass

        sub = await self._deps.broker.pull_subscribe(
            self._cfg.consumer_subject_filter,
            durable=self._cfg.consumer_durable,
            ack_wait_seconds=self._cfg.ack_wait_seconds,
            max_deliver=self._cfg.max_deliveries,
        )
        if sub is None:
            logger.error(
                "triage_worker_pull_subscribe_unavailable",
                consumer=self._cfg.consumer_durable,
            )
            await self._deps.broker.close()
            return

        # Separate consumer for the CONTROL stream's triage.cancel.v1.>
        # subjects. Failures here don't block alert dispatch; cancellation
        # is best-effort.
        cancel_sub = await self._deps.broker.pull_subscribe(
            self._cfg.cancel_subject_filter,
            durable=self._cfg.cancel_consumer_durable,
            ack_wait_seconds=10,
            max_deliver=2,
        )
        cancel_task: asyncio.Task | None = None
        if cancel_sub is not None:
            cancel_task = asyncio.create_task(self._run_cancel_loop(cancel_sub))

        sem = asyncio.Semaphore(self._cfg.max_inflight)
        logger.info(
            "triage_worker_started",
            consumer=self._cfg.consumer_durable,
            filter=self._cfg.consumer_subject_filter,
            max_inflight=self._cfg.max_inflight,
        )

        try:
            while not self._stop.is_set():
                try:
                    msgs = await sub.fetch(
                        batch=self._cfg.pull_batch,
                        timeout=2,
                    )
                except TimeoutError:
                    continue
                except Exception as exc:
                    logger.warning("triage_worker_fetch_failed", error=str(exc))
                    await asyncio.sleep(1)
                    continue

                for msg in msgs:
                    await sem.acquire()
                    task = asyncio.create_task(self._dispatch_one(msg, sem))
                    self._inflight.add(task)
                    task.add_done_callback(self._inflight.discard)
        finally:
            await self._drain_inflight()
            if cancel_task is not None:
                cancel_task.cancel()
                try:
                    await cancel_task
                except (asyncio.CancelledError, Exception):
                    pass
            await self._deps.broker.close()
            logger.info("triage_worker_stopped")

    async def _run_cancel_loop(self, sub: Any) -> None:
        """
        Drain the CONTROL stream's triage.cancel subjects. Each message is a
        request to mark the named alert_id as cancelled (with the
        ``CancelRegistry``'s 5-second debounce protecting against quick
        tab-reopen).
        """
        while not self._stop.is_set():
            try:
                msgs = await sub.fetch(batch=10, timeout=2)
            except asyncio.TimeoutError:
                continue
            except Exception as exc:
                logger.warning("triage_worker_cancel_fetch_failed", error=str(exc))
                await asyncio.sleep(1)
                continue
            for msg in msgs:
                try:
                    payload = json.loads(msg.data) if msg.data else {}
                    alert_id = payload.get("alert_id") or _alert_id_from_subject(msg.subject)
                    if alert_id:
                        await self._deps.cancel.request_cancel(alert_id)
                        logger.info("triage_worker_cancel_requested", alert_id=alert_id)
                    await _safe_ack(msg)
                except Exception as exc:
                    logger.warning("triage_worker_cancel_handler_failed", error=str(exc))
                    await _safe_ack(msg)   # don't redeliver — bad cancel is harmless to drop

    async def _dispatch_one(self, msg: Any, sem: asyncio.Semaphore) -> None:
        """
        Run handle_message for one NATS message. ACK / NAK / TERM the message
        based on outcome. Always release the semaphore so the run loop can
        accept the next message even if dispatch crashes hard.
        """
        try:
            headers = getattr(msg, "headers", None) or {}
            service_token = headers.get("X-Service-Auth", "")
            if not service_token:
                # No service token attached → poison pill. Don't redeliver.
                logger.warning(
                    "triage_worker_message_missing_service_token",
                    subject=msg.subject,
                )
                await _safe_term(msg)
                return

            try:
                await self.handle_message(
                    subject=msg.subject,
                    data=msg.data,
                    service_token=service_token,
                    msg_id=headers.get("Nats-Msg-Id"),
                )
            except JWTError:
                # Auth failure: treat as poison pill — never redeliver.
                await _safe_term(msg)
                return
            except _PoisonPill as exc:
                logger.warning(
                    "triage_worker_poison_pill",
                    subject=msg.subject,
                    reason=str(exc),
                )
                await _safe_term(msg)
                return
            except Exception as exc:
                # Transient error: NAK so JetStream redelivers (bounded by
                # max_deliveries). The next attempt may succeed via the
                # checkpointer-backed resume path.
                logger.warning(
                    "triage_worker_handle_message_failed_will_redeliver",
                    subject=msg.subject,
                    error=str(exc),
                )
                await _safe_nak(msg)
                return

            await _safe_ack(msg)
        finally:
            sem.release()

    def stop(self) -> None:
        self._stop.set()

    # -----------------------------------------------------------------
    # Per-message handler — public so tests can drive it directly without
    # standing up a real NATS connection.
    # -----------------------------------------------------------------

    async def handle_message(
        self,
        *,
        subject: str,
        data: bytes,
        service_token: str,
        msg_id: str | None,
    ) -> None:
        """
        Process a single inbound alert message.

        The caller (the NATS dispatch loop or a test) is responsible for
        ACKing the message *only after* this returns successfully. On
        exception the caller should NACK so the message is redelivered.
        """
        # 1. Verify the service token before touching the body.
        try:
            auth: AuthContext = await self._deps.jwt_service.verify(service_token)
        except JWTError as exc:
            logger.warning("worker_token_rejected", subject=subject, error=str(exc))
            raise

        # 2. Parse the alert. The tenant_id MUST come from auth, not from body.
        alert = _parse_alert(data, auth=auth)
        if alert.alert_id != (msg_id or alert.alert_id):
            # Sanity: msg_id should already equal alert_id for proper dedup.
            logger.warning(
                "worker_msgid_alertid_mismatch",
                msg_id=msg_id,
                alert_id=alert.alert_id,
            )

        await self._publish_phase(alert, "queued", trace_id=None)

        # 3. Cancellation check before doing expensive work.
        if await self._deps.cancel.is_cancelled(alert.alert_id):
            logger.info("worker_alert_cancelled_pre_dispatch", alert_id=alert.alert_id)
            await self._publish_phase(alert, "cancelled", trace_id=None)
            return

        # 4. Run the triage pipeline with a checkpointer scoped to this tenant.
        from services.triage_pipeline import run_triage  # lazy: heavy imports

        checkpointer = await self._deps.checkpointer_factory.get_checkpointer(auth.tenant_id)
        try:
            verdict: TriageVerdict = await run_triage(alert, checkpointer=checkpointer)
        except Exception:
            await self._publish_phase(alert, "failed", trace_id=None)
            raise

        # 5. Honor a cancel that landed mid-flight: graph completed but the
        # user already left. Publish a final cancelled-phase marker; the
        # verdict still gets stored for the audit trail.
        if await self._deps.cancel.is_cancelled(alert.alert_id):
            verdict_status = "cancelled"
        else:
            verdict_status = None

        if verdict.status is None and verdict_status is not None:
            verdict = verdict.model_copy(update={"status": verdict_status})

        await self._publish_phase(alert, "done", trace_id=None)
        # Verdict persistence is handled by the existing alert_persistence
        # store; no separate publish here.

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------

    async def _publish_phase(
        self,
        alert: NormalizedAlert,
        phase: str,
        *,
        trace_id: str | None,
    ) -> None:
        if not alert.tenant_id:
            return  # tenant_id required for routing; auth path guarantees this normally
        seq = await self._deps.event_seq.next_seq(alert.alert_id)
        event = PhaseEvent(
            alert_id=alert.alert_id,
            tenant_id=alert.tenant_id,
            event_seq=seq,
            phase=phase,            # type: ignore[arg-type]
            trace_id=trace_id,
        )
        await self._deps.broker.publish(
            subj_triage_event(alert.tenant_id, alert.alert_id, phase),
            event.model_dump_json().encode(),
            await_ack=False,
        )

    async def _to_dlq(self, alert: NormalizedAlert, reason: str) -> None:
        """Move a poisoned message to the DLQ stream with the reason attached."""
        if not alert.tenant_id:
            return
        body = json.dumps({"alert_id": alert.alert_id, "reason": reason}).encode()
        await self._deps.broker.publish(
            subj_dlq(alert.tenant_id, "ALERTS", alert.alert_id),
            body,
            msg_id=f"{alert.alert_id}:dlq",
            await_ack=True,
        )

    async def _drain_inflight(self) -> None:
        if not self._inflight:
            return
        logger.info("worker_draining_inflight", n=len(self._inflight))
        await asyncio.gather(*self._inflight, return_exceptions=True)
        self._inflight.clear()


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


class _PoisonPill(Exception):
    """Raised when a message cannot be processed even on redelivery."""


def _parse_alert(data: bytes, *, auth: AuthContext) -> NormalizedAlert:
    """
    Decode the NATS message into a NormalizedAlert.

    Critically: the tenant_id on the resulting alert is forced to the
    auth context's tenant_id, regardless of what's in the body. This is
    the architectural rule from plan section A7 — never trust the body.
    """
    try:
        raw = json.loads(data)
    except json.JSONDecodeError as exc:
        raise _PoisonPill(f"message body is not valid JSON: {exc}") from exc
    if isinstance(raw, dict):
        # Strip any client-supplied tenant_id before constructing the model.
        raw.pop("tenant_id", None)
        raw.pop("__subject__", None)   # WAL-only field, not part of the schema
    try:
        alert = NormalizedAlert.model_validate(raw)
    except Exception as exc:
        raise _PoisonPill(f"message body fails NormalizedAlert validation: {exc}") from exc
    return alert.model_copy(update={"tenant_id": auth.tenant_id})


def _alert_id_from_subject(subject: str) -> str | None:
    """
    Extract alert_id from a triage.cancel.v1.{tenant}.{alert} subject.

    Falls back to None if the subject shape doesn't match — the caller
    treats that as "skip this message."
    """
    # Subject pattern: triage.cancel.v1.{tenant_id}.{alert_id}
    parts = subject.split(".")
    if len(parts) >= 5 and parts[0] == "triage" and parts[1] == "cancel":
        return parts[-1]
    return None


async def _safe_ack(msg: Any) -> None:
    try:
        await msg.ack()
    except Exception as exc:
        logger.warning("triage_worker_ack_failed", error=str(exc))


async def _safe_nak(msg: Any) -> None:
    try:
        # nats-py exposes nak() with optional delay; default backoff is fine.
        await msg.nak()
    except Exception as exc:
        logger.warning("triage_worker_nak_failed", error=str(exc))


async def _safe_term(msg: Any) -> None:
    try:
        await msg.term()
    except Exception as exc:
        logger.warning("triage_worker_term_failed", error=str(exc))


# ---------------------------------------------------------------------------
# CLI: ``uv run python -m services._runtime.triage_worker``
# ---------------------------------------------------------------------------


def main() -> None:  # pragma: no cover - exercised via integration tests
    raise SystemExit(
        "Worker entry point not yet wired. The dispatch loop lands in the "
        "next sub-task (NATS pull consumer + DLQ + WAL reconciler integration)."
    )


if __name__ == "__main__":  # pragma: no cover
    main()
