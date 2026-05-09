"""
Unit tests for services/_runtime helpers.

These run without Redis or NATS — the helpers degrade gracefully when their
backing service is unreachable, so the unit test suite uses that mode.
Integration tests under @pytest.mark.integration require docker-compose.dev.yml.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest

from services._runtime.cancel import CancelRegistry
from services._runtime.event_seq import EventSequencer, _local_counters
from services._runtime.jwt_service import (
    JWTError,
    JWTService,
    SecretBundle,
)
from services._runtime.nats_broker import (
    STREAM_SPECS,
    subj_alert,
    subj_auth_revocation,
    subj_dlq,
    subj_feedback,
    subj_triage_cancel,
    subj_triage_event,
)
from services._runtime.tenant import (
    AuthContext,
    TenantContextError,
    get_tenant_id,
)

# ---------------------------------------------------------------------------
# tenant.get_tenant_id
# ---------------------------------------------------------------------------


def test_get_tenant_id_from_auth_context() -> None:
    auth = AuthContext(user_id="u1", tenant_id="acme", audience="worker")
    assert get_tenant_id(auth) == "acme"


def test_get_tenant_id_from_request_state() -> None:
    auth = AuthContext(user_id="u1", tenant_id="globex", audience="worker")
    request = SimpleNamespace(state=SimpleNamespace(auth=auth))
    assert get_tenant_id(request) == "globex"


def test_get_tenant_id_from_mapping_with_auth_key() -> None:
    auth = AuthContext(user_id="u1", tenant_id="initech", audience="worker")
    msg = {"auth": auth, "data": {"tenant_id": "ATTACKER"}}  # body must be ignored
    assert get_tenant_id(msg) == "initech"


def test_get_tenant_id_rejects_missing_context() -> None:
    with pytest.raises(TenantContextError):
        get_tenant_id({"data": {"tenant_id": "ATTACKER"}})


def test_get_tenant_id_rejects_empty_tenant() -> None:
    auth = AuthContext(user_id="u1", tenant_id="   ", audience="worker")
    with pytest.raises(TenantContextError):
        get_tenant_id(auth)


# ---------------------------------------------------------------------------
# event_seq (local-fallback mode; no Redis)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_local_counters() -> None:
    _local_counters.clear()
    yield
    _local_counters.clear()


async def test_event_seq_monotonic_per_alert() -> None:
    seq = EventSequencer(redis_url="redis://nonexistent:6379/0")
    seq._client = None  # force local-fallback path
    a = await seq.next_seq("alert-1")
    b = await seq.next_seq("alert-1")
    c = await seq.next_seq("alert-1")
    assert (a, b, c) == (1, 2, 3)


async def test_event_seq_independent_per_alert() -> None:
    seq = EventSequencer(redis_url="redis://nonexistent:6379/0")
    seq._client = None
    assert await seq.next_seq("alert-A") == 1
    assert await seq.next_seq("alert-B") == 1
    assert await seq.next_seq("alert-A") == 2
    assert await seq.current_seq("alert-A") == 2
    assert await seq.current_seq("alert-B") == 1


async def test_event_seq_current_without_advance() -> None:
    seq = EventSequencer(redis_url="redis://nonexistent:6379/0")
    seq._client = None
    assert await seq.current_seq("alert-X") == 0
    await seq.next_seq("alert-X")
    assert await seq.current_seq("alert-X") == 1
    assert await seq.current_seq("alert-X") == 1   # no advance


# ---------------------------------------------------------------------------
# cancel (Redis-required for full behavior; here we test no-Redis no-op path
# and direct-flag path through a shim)
# ---------------------------------------------------------------------------


class _FakeRedis:
    """Minimal in-process Redis stub for unit testing CancelRegistry."""

    def __init__(self) -> None:
        self.kv: dict[str, tuple[str, float]] = {}   # key -> (value, exp_ts)

    async def setex(self, key: str, ttl: int, value: str) -> None:
        self.kv[key] = (value, time.time() + ttl)

    async def get(self, key: str) -> str | None:
        if key not in self.kv:
            return None
        value, exp = self.kv[key]
        if time.time() > exp:
            self.kv.pop(key, None)
            return None
        return value

    async def delete(self, key: str) -> None:
        self.kv.pop(key, None)

    async def aclose(self) -> None:
        return None


async def test_cancel_grace_window_lets_revoke_win() -> None:
    reg = CancelRegistry(redis_url="redis://nonexistent:6379/0", grace_seconds=1)
    reg._client = _FakeRedis()
    await reg.request_cancel("alert-1")
    # Reopen the tab quickly; cancel should be aborted before it fires.
    await reg.revoke_cancel("alert-1")
    await asyncio.sleep(1.2)
    assert await reg.is_cancelled("alert-1") is False
    await reg.close()


async def test_cancel_fires_after_grace_when_not_revoked() -> None:
    reg = CancelRegistry(redis_url="redis://nonexistent:6379/0", grace_seconds=1)
    reg._client = _FakeRedis()
    await reg.request_cancel("alert-2")
    await asyncio.sleep(1.2)
    assert await reg.is_cancelled("alert-2") is True
    await reg.close()


async def test_cancel_request_is_idempotent_debounces_timer() -> None:
    reg = CancelRegistry(redis_url="redis://nonexistent:6379/0", grace_seconds=1)
    reg._client = _FakeRedis()
    await reg.request_cancel("alert-3")
    await asyncio.sleep(0.5)
    await reg.request_cancel("alert-3")   # restart the timer
    await asyncio.sleep(0.7)
    # Original timer would have fired by now (~1.2s); restart pushed it out.
    assert await reg.is_cancelled("alert-3") is False
    await asyncio.sleep(0.6)
    assert await reg.is_cancelled("alert-3") is True
    await reg.close()


# ---------------------------------------------------------------------------
# jwt_service (HS256 sign/verify, audience, rotation, revocation)
# ---------------------------------------------------------------------------


def _bundle(current: str = "secret-A", previous: str | None = None) -> SecretBundle:
    return SecretBundle(audience="worker", current=current, previous=previous)


def _provider(bundle: SecretBundle):
    def _p() -> SecretBundle:
        return bundle
    return _p


def _bff_provider(bundle: SecretBundle):
    """Mint-side provider (issuer = bff) for tokens addressed to ``aud=worker``."""
    return _provider(SecretBundle(audience="bff", current=bundle.current, previous=bundle.previous))


async def test_jwt_mint_and_verify_roundtrip() -> None:
    bundle = SecretBundle(audience="bff", current="s1")
    bff = JWTService(audience="bff", bundle_provider=_provider(bundle))
    worker_bundle = SecretBundle(audience="worker", current="s1")  # shared in test
    worker = JWTService(audience="worker", bundle_provider=_provider(worker_bundle))

    token = bff.mint(subject="user-42", tenant_id="acme", target_audience="worker")
    auth = await worker.verify(token)
    assert auth.tenant_id == "acme"
    assert auth.audience == "worker"
    assert auth.user_id == "user-42"


async def test_jwt_audience_mismatch_rejected() -> None:
    bundle = SecretBundle(audience="bff", current="s1")
    bff = JWTService(audience="bff", bundle_provider=_provider(bundle))
    ingest = JWTService(
        audience="ingest",
        bundle_provider=_provider(SecretBundle(audience="ingest", current="s1")),
    )
    token = bff.mint(subject="u", tenant_id="acme", target_audience="worker")
    with pytest.raises(JWTError):
        await ingest.verify(token)


async def test_jwt_signature_tamper_rejected() -> None:
    bundle = SecretBundle(audience="bff", current="s1")
    bff = JWTService(audience="bff", bundle_provider=_provider(bundle))
    worker = JWTService(
        audience="worker",
        bundle_provider=_provider(SecretBundle(audience="worker", current="s1")),
    )
    token = bff.mint(subject="u", tenant_id="acme", target_audience="worker")
    # Flip a character in the signature segment.
    head, payload, sig = token.split(".")
    bad = ".".join([head, payload, sig[:-1] + ("a" if sig[-1] != "a" else "b")])
    with pytest.raises(JWTError):
        await worker.verify(bad)


async def test_jwt_rotation_overlap_accepts_previous_secret() -> None:
    # Issued under old secret.
    old_bff = JWTService(
        audience="bff",
        bundle_provider=_provider(SecretBundle(audience="bff", current="old")),
    )
    token = old_bff.mint(subject="u", tenant_id="acme", target_audience="worker")
    # Worker has rotated: current=new, previous=old. Should still verify.
    worker = JWTService(
        audience="worker",
        bundle_provider=_provider(
            SecretBundle(audience="worker", current="new", previous="old")
        ),
    )
    auth = await worker.verify(token)
    assert auth.tenant_id == "acme"


async def test_jwt_revocation_blocks_verify() -> None:
    revoked: set[str] = set()

    async def _is_revoked(jti: str) -> bool:
        return jti in revoked

    bff = JWTService(
        audience="bff",
        bundle_provider=_provider(SecretBundle(audience="bff", current="s1")),
    )
    worker = JWTService(
        audience="worker",
        bundle_provider=_provider(SecretBundle(audience="worker", current="s1")),
        revoked_jti_checker=_is_revoked,
    )
    token = bff.mint(subject="u", tenant_id="acme", target_audience="worker")
    auth = await worker.verify(token)
    revoked.add(auth.jti)
    with pytest.raises(JWTError):
        await worker.verify(token)


# ---------------------------------------------------------------------------
# nats_broker: subject naming + stream specs
# ---------------------------------------------------------------------------


def test_subject_constructors_carry_v1_and_tenant() -> None:
    assert subj_alert("acme", "splunk", "abc") == "alerts.v1.acme.splunk.abc"
    assert subj_triage_event("acme", "abc", "extract") == "triage.events.v1.acme.abc.extract"
    assert subj_triage_cancel("acme", "abc") == "triage.cancel.v1.acme.abc"
    assert subj_auth_revocation("acme", "u-1") == "auth.revocations.v1.acme.u-1"
    assert subj_feedback("acme", "abc") == "feedback.v1.acme.abc"
    assert subj_dlq("acme", "ALERTS", "abc") == "dlq.v1.acme.ALERTS.abc"


def test_stream_specs_cover_all_advertised_streams() -> None:
    names = {s.name for s in STREAM_SPECS}
    assert names == {"ALERTS", "TRIAGE_EVENTS", "CONTROL", "FEEDBACK", "DLQ"}
    # CONTROL carries both cancel and revocation subjects.
    control = next(s for s in STREAM_SPECS if s.name == "CONTROL")
    assert "triage.cancel.v1.>" in control.subjects
    assert "auth.revocations.v1.>" in control.subjects
