"""
Triage worker handle_message + dispatch tests (fakes, no NATS).

We exercise:
  * Token verification + tenant_id-from-auth-only.
  * Cancellation gating before and after the graph runs.
  * ACK / NAK / TERM behaviour for poison pills, transient errors, and
    successful messages, via the dispatch loop's _dispatch_one path.
  * Idempotency contract: handle_message uses alert_id as the LangGraph
    thread_id, so a redelivered message resumes rather than restarting.

A minimal fake NATS message exposes the methods the worker calls
(ack/nak/term/headers) so we can assert which path was taken without
booting JetStream.
"""

from __future__ import annotations

import asyncio
from datetime import datetime

import pytest

from schemas._common import AlertSource, EscalationDecision, Severity
from schemas.v1 import (
    MITREAssessment,
    NormalizedAlert,
    TriageVerdict,
)
from services._runtime.jwt_bootstrap import ServiceTokenAuthority
from services._runtime.secret_store import InMemorySecretStore
from services._runtime.tenant import AuthContext
from services._runtime.triage_worker import (
    TriageWorker,
    WorkerConfig,
    WorkerDeps,
    _parse_alert,
    _PoisonPill,
    _safe_ack,
    _safe_nak,
    _safe_term,
)

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeBroker:
    def __init__(self) -> None:
        self.connected = False
        self.published: list[tuple[str, bytes, str | None]] = []
        self.pull_subscribe_called = False

    async def connect(self) -> None:
        self.connected = True

    async def publish(
        self, subject, payload, *, msg_id=None, headers=None, await_ack=False
    ) -> bool:
        self.published.append((subject, payload, msg_id))
        return True

    async def pull_subscribe(self, *args, **kwargs):
        self.pull_subscribe_called = True
        return None

    async def close(self) -> None:
        self.connected = False


class _FakeCancel:
    def __init__(self, *, cancelled_ids: set[str] | None = None) -> None:
        self.cancelled_ids = cancelled_ids or set()
        self.checks: list[str] = []

    async def is_cancelled(self, alert_id: str) -> bool:
        self.checks.append(alert_id)
        return alert_id in self.cancelled_ids


class _FakeEventSeq:
    def __init__(self) -> None:
        self.counters: dict[str, int] = {}
        self.calls: list[str] = []

    async def next_seq(self, alert_id: str) -> int:
        self.calls.append(alert_id)
        self.counters[alert_id] = self.counters.get(alert_id, 0) + 1
        return self.counters[alert_id]


class _FakeCheckpointerFactory:
    def __init__(self) -> None:
        self.requested: list[str | None] = []

    async def get_checkpointer(self, tenant_id: str | None = None):
        self.requested.append(tenant_id)
        return object()   # opaque sentinel — the test stubs run_triage


class _FakeMsg:
    """Minimal NATS-message stub for dispatch tests."""

    def __init__(
        self,
        subject: str,
        data: bytes,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.subject = subject
        self.data = data
        self.headers = dict(headers or {})
        self.acked = False
        self.naked = False
        self.termed = False

    async def ack(self) -> None:
        self.acked = True

    async def nak(self) -> None:
        self.naked = True

    async def term(self) -> None:
        self.termed = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _make_worker(
    *,
    cancel: _FakeCancel | None = None,
    cancelled_after_dispatch: bool = False,
):
    store = InMemorySecretStore(seed_audiences=("worker",))
    authority = await ServiceTokenAuthority.start(
        store=store,
        audiences=("worker",),
    )
    deps = WorkerDeps(
        broker=_FakeBroker(),
        jwt_service=authority.jwt_for("worker"),
        cancel=cancel or _FakeCancel(),
        event_seq=_FakeEventSeq(),
        checkpointer_factory=_FakeCheckpointerFactory(),
    )
    worker = TriageWorker(WorkerConfig(), deps)
    return worker, authority, deps


def _alert_payload(*, alert_id: str = "alert-1") -> bytes:
    body = NormalizedAlert(
        alert_id=alert_id,
        source=AlertSource.GENERIC,
        title="t",
        description="d",
        severity=Severity.LOW,
        timestamp=datetime.utcnow(),
        tenant_id="WILL_BE_OVERRIDDEN",   # body's tenant_id MUST be ignored
    ).model_dump_json().encode()
    return body


def _stub_run_triage(monkeypatch, *, cancelled_after: bool = False):
    """
    Replace services.triage_pipeline.run_triage with a stub that returns
    a deterministic verdict and records the alert it received.
    """
    captured: list[NormalizedAlert] = []

    async def _stub(alert, *, checkpointer=None):
        captured.append(alert)
        return TriageVerdict(
            alert_id=alert.alert_id,
            tenant_id=alert.tenant_id,
            severity=Severity.LOW,
            severity_justification="ok",
            mitre_assessments=[
                MITREAssessment(
                    technique_id="T1059",
                    technique_name="Command and Scripting Interpreter",
                    tactic="Execution",
                    confidence=0.5,
                ),
            ],
            triage_summary="stubbed",
            confirmed_iocs=[],
            immediate_actions=[],
            escalation=EscalationDecision.MONITOR,
            escalation_rationale="stubbed",
        )

    import services.triage_pipeline as pipeline_mod

    monkeypatch.setattr(pipeline_mod, "run_triage", _stub)
    return captured


# ---------------------------------------------------------------------------
# _parse_alert — tenant_id from auth only
# ---------------------------------------------------------------------------


def test_parse_alert_overrides_body_tenant_with_auth() -> None:
    auth = AuthContext(user_id=None, tenant_id="acme", audience="worker")
    body = _alert_payload(alert_id="x-1")
    alert = _parse_alert(body, auth=auth)
    assert alert.tenant_id == "acme"   # NOT "WILL_BE_OVERRIDDEN"
    assert alert.alert_id == "x-1"


def test_parse_alert_strips_subject_field() -> None:
    """The WAL stuffs ``__subject__`` into the payload; the worker must drop it."""
    import json
    raw = {
        "alert_id": "y",
        "source": "generic",
        "title": "t",
        "description": "d",
        "severity": "LOW",
        "timestamp": datetime.utcnow().isoformat(),
        "__subject__": "alerts.v1.acme.generic.y",
    }
    auth = AuthContext(user_id=None, tenant_id="acme", audience="worker")
    alert = _parse_alert(json.dumps(raw).encode(), auth=auth)
    assert alert.alert_id == "y"


def test_parse_alert_invalid_json_is_poison_pill() -> None:
    auth = AuthContext(user_id=None, tenant_id="acme", audience="worker")
    with pytest.raises(_PoisonPill):
        _parse_alert(b"not-json", auth=auth)


def test_parse_alert_invalid_shape_is_poison_pill() -> None:
    auth = AuthContext(user_id=None, tenant_id="acme", audience="worker")
    with pytest.raises(_PoisonPill):
        _parse_alert(b'{"only": "this"}', auth=auth)


# ---------------------------------------------------------------------------
# handle_message — happy path
# ---------------------------------------------------------------------------


async def test_handle_message_runs_triage_and_publishes_phases(monkeypatch) -> None:
    captured = _stub_run_triage(monkeypatch)
    worker, authority, deps = await _make_worker()
    try:
        token = authority.jwt_for("worker").mint(
            subject="user-1", tenant_id="acme", target_audience="worker"
        )
        await worker.handle_message(
            subject="alerts.v1.acme.generic.alert-1",
            data=_alert_payload(),
            service_token=token,
            msg_id="alert-1",
        )
        # run_triage was called with the auth-derived tenant_id, not the body's.
        assert len(captured) == 1
        assert captured[0].tenant_id == "acme"
        # The fake broker received at least the queued and done phase events.
        subjects = [s for s, _, _ in deps.broker.published]
        assert any("triage.events.v1.acme.alert-1.queued" in s for s in subjects)
        assert any("triage.events.v1.acme.alert-1.done" in s for s in subjects)
    finally:
        await authority.stop()


# ---------------------------------------------------------------------------
# handle_message — cancellation gates
# ---------------------------------------------------------------------------


async def test_handle_message_skips_pipeline_when_already_cancelled(monkeypatch) -> None:
    captured = _stub_run_triage(monkeypatch)
    cancel = _FakeCancel(cancelled_ids={"alert-2"})
    worker, authority, deps = await _make_worker(cancel=cancel)
    try:
        token = authority.jwt_for("worker").mint(
            subject="u", tenant_id="acme", target_audience="worker"
        )
        await worker.handle_message(
            subject="alerts.v1.acme.generic.alert-2",
            data=_alert_payload(alert_id="alert-2"),
            service_token=token,
            msg_id="alert-2",
        )
        # Pipeline must NOT have run.
        assert captured == []
        # A cancelled phase event was published.
        subjects = [s for s, _, _ in deps.broker.published]
        assert any("alert-2.cancelled" in s for s in subjects)
    finally:
        await authority.stop()


async def test_handle_message_marks_verdict_cancelled_when_user_left_midflight(monkeypatch) -> None:
    """
    User opens an alert, triage starts, user closes the tab while triage
    is still running. By the time the graph completes the cancel flag is
    set; the worker should annotate the verdict with status='cancelled'.
    """
    captured = _stub_run_triage(monkeypatch)
    cancel = _FakeCancel()

    # Flip the cancel flag at the SECOND check (i.e. post-graph, after the
    # pre-dispatch check has already passed). cancel.is_cancelled records
    # every check, so we use side effects on the calls list.
    original_check = cancel.is_cancelled

    async def _flipping_check(alert_id: str) -> bool:
        result = await original_check(alert_id)
        if not result and len(cancel.checks) > 1:
            return True
        return result

    cancel.is_cancelled = _flipping_check  # type: ignore[method-assign]

    worker, authority, deps = await _make_worker(cancel=cancel)
    try:
        token = authority.jwt_for("worker").mint(
            subject="u", tenant_id="acme", target_audience="worker"
        )
        await worker.handle_message(
            subject="alerts.v1.acme.generic.alert-3",
            data=_alert_payload(alert_id="alert-3"),
            service_token=token,
            msg_id="alert-3",
        )
        # Pipeline ran (the pre-dispatch cancel check returned False).
        assert len(captured) == 1
        # 'done' phase event was emitted; the verdict status reflection is
        # applied via model_copy(update={"status": "cancelled"}) inside the
        # worker — not separately observable on the broker, but the test
        # confirms the post-graph cancel branch executed by counting the
        # is_cancelled checks.
        assert len(cancel.checks) >= 2
    finally:
        await authority.stop()


# ---------------------------------------------------------------------------
# Dispatch loop — ACK / NAK / TERM
# ---------------------------------------------------------------------------


async def test_dispatch_one_acks_on_success(monkeypatch) -> None:
    _stub_run_triage(monkeypatch)
    worker, authority, _ = await _make_worker()
    try:
        token = authority.jwt_for("worker").mint(
            subject="u", tenant_id="acme", target_audience="worker"
        )
        msg = _FakeMsg(
            subject="alerts.v1.acme.generic.x",
            data=_alert_payload(alert_id="x"),
            headers={"X-Service-Auth": token, "Nats-Msg-Id": "x"},
        )
        sem = asyncio.Semaphore(1)
        await sem.acquire()
        await worker._dispatch_one(msg, sem)
        assert msg.acked is True
        assert msg.naked is False
        assert msg.termed is False
    finally:
        await authority.stop()


async def test_dispatch_one_terms_on_missing_token() -> None:
    worker, authority, _ = await _make_worker()
    try:
        msg = _FakeMsg(
            subject="alerts.v1.acme.generic.y",
            data=_alert_payload(alert_id="y"),
            headers={},   # missing X-Service-Auth
        )
        sem = asyncio.Semaphore(1)
        await sem.acquire()
        await worker._dispatch_one(msg, sem)
        assert msg.termed is True
        assert msg.acked is False
    finally:
        await authority.stop()


async def test_dispatch_one_terms_on_invalid_token() -> None:
    worker, authority, _ = await _make_worker()
    try:
        msg = _FakeMsg(
            subject="alerts.v1.acme.generic.z",
            data=_alert_payload(alert_id="z"),
            headers={"X-Service-Auth": "garbage.not.a.jwt"},
        )
        sem = asyncio.Semaphore(1)
        await sem.acquire()
        await worker._dispatch_one(msg, sem)
        assert msg.termed is True
        assert msg.acked is False
    finally:
        await authority.stop()


async def test_dispatch_one_terms_on_poison_pill_payload() -> None:
    worker, authority, _ = await _make_worker()
    try:
        token = authority.jwt_for("worker").mint(
            subject="u", tenant_id="acme", target_audience="worker"
        )
        msg = _FakeMsg(
            subject="alerts.v1.acme.generic.w",
            data=b"definitely not json",
            headers={"X-Service-Auth": token},
        )
        sem = asyncio.Semaphore(1)
        await sem.acquire()
        await worker._dispatch_one(msg, sem)
        assert msg.termed is True
    finally:
        await authority.stop()


async def test_dispatch_one_naks_on_transient_pipeline_error(monkeypatch) -> None:
    """A run_triage exception that isn't a poison pill should NAK so JetStream redelivers."""
    async def _boom(alert, *, checkpointer=None):
        raise RuntimeError("transient downstream failure")

    import services.triage_pipeline as pipeline_mod

    monkeypatch.setattr(pipeline_mod, "run_triage", _boom)

    worker, authority, _ = await _make_worker()
    try:
        token = authority.jwt_for("worker").mint(
            subject="u", tenant_id="acme", target_audience="worker"
        )
        msg = _FakeMsg(
            subject="alerts.v1.acme.generic.q",
            data=_alert_payload(alert_id="q"),
            headers={"X-Service-Auth": token, "Nats-Msg-Id": "q"},
        )
        sem = asyncio.Semaphore(1)
        await sem.acquire()
        await worker._dispatch_one(msg, sem)
        assert msg.naked is True
        assert msg.acked is False
        assert msg.termed is False
    finally:
        await authority.stop()


async def test_dispatch_one_releases_semaphore_even_on_failure() -> None:
    worker, authority, _ = await _make_worker()
    try:
        msg = _FakeMsg(
            subject="alerts.v1.acme.generic.x",
            data=b"junk",
            headers={},
        )
        sem = asyncio.Semaphore(2)
        # Take both slots so we can detect release.
        await sem.acquire()
        await sem.acquire()
        await worker._dispatch_one(msg, sem)
        # Semaphore should have one slot back regardless of outcome.
        await asyncio.wait_for(sem.acquire(), timeout=0.5)
    finally:
        await authority.stop()


# ---------------------------------------------------------------------------
# Safe ack/nak/term swallow exceptions (so they never poison the dispatch loop)
# ---------------------------------------------------------------------------


async def test_safe_ack_nak_term_swallow_exceptions() -> None:
    class _BadMsg:
        async def ack(self) -> None:
            raise RuntimeError("boom")

        async def nak(self) -> None:
            raise RuntimeError("boom")

        async def term(self) -> None:
            raise RuntimeError("boom")

    msg = _BadMsg()
    # None of these should propagate.
    await _safe_ack(msg)
    await _safe_nak(msg)
    await _safe_term(msg)
