"""
Glue between FastAPI and the Architecture-2 runtime services.

Kept separate from app/main.py so the existing in-process triage path is
not entangled with the new NATS-based path. Activation is gated by
``Settings.ingest_via_nats`` — when off, this module does nothing and the
app behaves exactly as before.

Lifecycle:

    on startup → build NatsBroker + IngestReconciler + JWTService and
                 stash them on app.state. Start the reconciler loop.

    on request → ingest path calls ``enqueue_via_nats(alert, app)`` which
                 writes WAL, attempts publish, returns whether it landed
                 inline or was deferred to the reconciler.

    on shutdown → stop reconciler, close broker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog

from app.config import Settings
from schemas.v1 import NormalizedAlert
from services._runtime.audit import AuditStore
from services._runtime.ingest_reconciler import IngestReconciler
from services._runtime.jwt_bootstrap import ServiceTokenAuthority
from services._runtime.jwt_service import JWTService
from services._runtime.nats_broker import NatsBroker, subj_alert
from services._runtime.secret_store import PostgresSecretStore

logger = structlog.get_logger(__name__)


@dataclass
class RuntimeState:
    """Container for runtime services. Lives on ``app.state.runtime``."""

    broker: NatsBroker | None = None
    reconciler: IngestReconciler | None = None
    ingest_jwt: JWTService | None = None
    audit: AuditStore | None = None
    token_authority: ServiceTokenAuthority | None = None


def _subject_for_alert(alert: NormalizedAlert) -> str:
    """
    Compute the ALERTS subject from a *typed* NormalizedAlert.

    We deliberately do NOT read tenant_id from a dict here — that would
    bypass the lint that prevents body-tenant-id confusion. The alert
    object's tenant_id was set from the verified auth context upstream.
    """
    tenant_id = alert.tenant_id or "default"
    source = alert.source.value if alert.source else "generic"
    return subj_alert(tenant_id, source, alert.alert_id)


def _wal_subject_resolver(payload: dict[str, Any]) -> str:
    """
    Reconciler subject resolver. Reads the subject the WAL entry recorded
    at ingest time — never re-derives it from untyped payload fields.
    """
    subject = payload.get("__subject__")
    if not subject:
        # Defensive: a malformed WAL entry without the precomputed subject
        # is treated as unrouteable. The reconciler will leave it pending
        # until max_age expires, then move to DLQ.
        raise KeyError("WAL entry missing precomputed __subject__")
    return subject


async def startup(app: Any, settings: Settings) -> None:
    """Wire runtime services onto ``app.state``. Idempotent.

    The audit store is wired regardless of ``ingest_via_nats`` because
    raw-payload retention is always-on once Redis is reachable. The NATS
    broker + reconciler are only wired when the flag is set.
    """
    state = RuntimeState()
    app.state.runtime = state

    if settings.audit_enabled:
        state.audit = AuditStore(
            redis_url=settings.redis_url,
            default_ttl_seconds=settings.audit_default_ttl_sec,
        )

    # Service-token authority: always wired so /verdict/{alert_id} can
    # validate inbound service JWTs once the BFF is in front. Falls back
    # to in-memory if Postgres is unreachable.
    try:
        state.token_authority = await ServiceTokenAuthority.start(
            store=PostgresSecretStore(dsn=settings.secrets_pg_url),
            audiences=("ingest", "worker", "gateway", "bff_user"),
        )
        state.ingest_jwt = state.token_authority.jwt_for("ingest")
    except Exception as exc:
        logger.warning("runtime_token_authority_start_failed", error=str(exc))

    if not settings.ingest_via_nats:
        logger.info("runtime_nats_disabled", audit_enabled=settings.audit_enabled)
        return

    broker = NatsBroker(
        servers=settings.nats_url,
        creds_path=settings.nats_creds_path or None,
        name="soc-triage-ingest",
    )
    await broker.connect()
    state.broker = broker

    reconciler = IngestReconciler(
        broker=broker,
        redis_url=settings.redis_url,
        publish_subject_for=_wal_subject_resolver,
    )
    await reconciler.start()
    state.reconciler = reconciler

    logger.info("runtime_nats_enabled", nats_url=settings.nats_url)


async def shutdown(app: Any) -> None:
    state: RuntimeState | None = getattr(app.state, "runtime", None)
    if state is None:
        return
    if state.reconciler is not None:
        await state.reconciler.stop()
    if state.broker is not None:
        await state.broker.close()
    if state.audit is not None:
        await state.audit.close()
    if state.token_authority is not None:
        await state.token_authority.stop()


async def record_raw_payload(app: Any, alert: NormalizedAlert, raw: dict[str, Any]) -> None:
    """Best-effort audit write. Never raises into the ingest path."""
    state: RuntimeState | None = getattr(app.state, "runtime", None)
    if state is None or state.audit is None:
        return
    try:
        await state.audit.record_raw_payload(alert.alert_id, alert.tenant_id, raw)
    except Exception as exc:
        logger.warning("audit_record_failed", alert_id=alert.alert_id, error=str(exc))


async def attach_verified_service_token(app: Any, request: Any) -> None:
    """
    Best-effort: if the request carries an Authorization: Bearer <jwt> for
    audience=ingest, verify it and stash the AuthContext on request.state.

    Used by /verdict tenant-check and any route that wants to surface
    tenant_id from a BFF-issued service JWT. Silently no-ops on missing /
    invalid tokens — falling back to API-key auth.
    """
    state: RuntimeState | None = getattr(app.state, "runtime", None)
    if state is None or state.ingest_jwt is None:
        return
    auth_header: str = request.headers.get("authorization", "") or ""
    if not auth_header.lower().startswith("bearer "):
        return
    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return
    try:
        request.state.auth = await state.ingest_jwt.verify(token)
    except Exception:
        # Invalid service token: don't pollute request.state. The caller's
        # legacy X-API-Key path still applies.
        return


async def enqueue_via_nats(app: Any, alert: NormalizedAlert) -> bool:
    """
    Persist the alert to the WAL and try inline NATS publish.

    Returns True if the alert was accepted (inline publish succeeded OR
    deferred to the reconciler). Returns False only if the runtime is
    not enabled — caller should fall back to the in-process path in that
    case.
    """
    state: RuntimeState | None = getattr(app.state, "runtime", None)
    if state is None or state.broker is None or state.reconciler is None:
        return False

    # Subject is derived from the typed alert (tenant_id from auth context),
    # never from a dict lookup that the lint would flag.
    subject = _subject_for_alert(alert)

    payload = alert.model_dump(mode="json")
    # Bake the precomputed subject into the WAL entry so the reconciler
    # never has to re-derive it from untyped fields.
    payload["__subject__"] = subject
    body = alert.model_dump_json().encode()

    # 1. WAL first — guarantees the alert is durable even if both the
    # NATS publish and the worker crash before processing.
    await state.reconciler.write_ahead(alert.alert_id, payload)

    # 2. Try the inline publish. We await the JetStream ack here because
    # the ingest contract is "the alert is durable when we return 202."
    ok = await state.broker.publish(
        subject,
        body,
        msg_id=alert.alert_id,
        await_ack=True,
    )
    if ok:
        # Inline path succeeded — remove the WAL entry so the reconciler
        # doesn't double-publish.
        await state.reconciler.mark_published(alert.alert_id)
    else:
        # Inline failed; the reconciler will retry from the WAL.
        logger.warning("ingest_inline_publish_failed", alert_id=alert.alert_id)
    return True
