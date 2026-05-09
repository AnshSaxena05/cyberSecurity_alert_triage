"""
HTTP-level tests for /verdict/{alert_id} (auth + deprecation) and /audit/{alert_id}.

These exercise the FastAPI app via TestClient, not the underlying
persistence directly, so we cover the actual request/response surface.
The persistence and audit stores are seeded by hand so the tests run
without Redis, NATS, or any LLM credentials.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app
from schemas._common import AlertSource, EscalationDecision, Severity
from schemas.v1 import (
    MITREAssessment,
    NormalizedAlert,
    TriageVerdict,
)

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _make_alert(alert_id: str = "alpha", *, tenant_id: str | None = "acme") -> NormalizedAlert:
    return NormalizedAlert(
        alert_id=alert_id,
        source=AlertSource.GENERIC,
        title="t",
        description="d",
        severity=Severity.LOW,
        timestamp=datetime.utcnow(),
        tenant_id=tenant_id,
    )


def _make_verdict(alert_id: str, *, tenant_id: str | None = "acme") -> TriageVerdict:
    return TriageVerdict(
        alert_id=alert_id,
        tenant_id=tenant_id,
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
        triage_summary="stub",
        confirmed_iocs=[],
        immediate_actions=[],
        escalation=EscalationDecision.MONITOR,
        escalation_rationale="stub",
    )


@pytest.fixture
def client(monkeypatch) -> TestClient:
    # Reset cached settings so per-test env-var changes are visible.
    get_settings.cache_clear()
    return TestClient(app)


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch):
    """Each test starts with no runtime state and a known API key."""
    monkeypatch.setenv("API_KEY", "test-key")
    monkeypatch.setenv("VERDICT_AUTH_REQUIRED", "false")
    monkeypatch.setenv("AUDIT_ENABLED", "true")
    monkeypatch.setenv("INGEST_VIA_NATS", "false")
    get_settings.cache_clear()
    # Drop any runtime state from prior tests.
    if hasattr(app.state, "runtime"):
        app.state.runtime = None
    yield
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# /verdict/{alert_id} — deprecation window (flag off)
# ---------------------------------------------------------------------------


async def _seed_verdict(alert_id: str, tenant_id: str = "acme") -> None:
    from services.alert_persistence import get_alert_persistence

    persistence = get_alert_persistence()
    await persistence.put_alert(_make_alert(alert_id, tenant_id=tenant_id))
    await persistence.put_verdict(alert_id, _make_verdict(alert_id, tenant_id=tenant_id))
    await persistence.set_job(alert_id, "complete")


def test_verdict_returns_with_deprecation_header_when_flag_off(client) -> None:
    import asyncio
    asyncio.run(_seed_verdict("alpha"))

    r = client.get("/verdict/alpha")
    assert r.status_code == 200
    assert r.headers.get("Deprecation") == "true"
    assert r.headers.get("Sunset")    # any non-empty date string
    body = r.json()
    assert body["alert_id"] == "alpha"
    assert body["status"] == "complete"


def test_verdict_returns_404_for_unknown_alert(client) -> None:
    r = client.get("/verdict/never-existed")
    assert r.status_code == 404


def test_verdict_returns_with_api_key_and_still_emits_deprecation_when_flag_off(client) -> None:
    import asyncio
    asyncio.run(_seed_verdict("beta"))
    r = client.get("/verdict/beta", headers={"X-API-Key": "test-key"})
    assert r.status_code == 200
    # Deprecation header is present until the flag is flipped.
    assert r.headers.get("Deprecation") == "true"


# ---------------------------------------------------------------------------
# /verdict/{alert_id} — post-cutover (flag on)
# ---------------------------------------------------------------------------


def test_verdict_rejects_unauthenticated_when_flag_on(monkeypatch, client) -> None:
    monkeypatch.setenv("VERDICT_AUTH_REQUIRED", "true")
    get_settings.cache_clear()
    import asyncio
    asyncio.run(_seed_verdict("gamma"))
    r = client.get("/verdict/gamma")
    assert r.status_code == 401


def test_verdict_accepts_with_api_key_when_flag_on(monkeypatch, client) -> None:
    monkeypatch.setenv("VERDICT_AUTH_REQUIRED", "true")
    get_settings.cache_clear()
    import asyncio
    asyncio.run(_seed_verdict("delta"))
    r = client.get("/verdict/delta", headers={"X-API-Key": "test-key"})
    assert r.status_code == 200
    # Once the flag is on, no Deprecation header.
    assert "Deprecation" not in r.headers


def test_verdict_cross_tenant_request_is_rejected_when_auth_carries_tenant(
    monkeypatch, client,
) -> None:
    """
    When an inbound request carries a verified service JWT (request.state.auth)
    whose tenant_id does NOT match the verdict's tenant_id, return 403 — never
    leak the verdict by returning 200, and never return 404 (which would let
    a probe distinguish "exists but not yours" from "doesn't exist").

    We monkey-patch the helper that reads tenant_id off request.state instead
    of installing real middleware — the latter pollutes ``app.user_middleware``
    globally and breaks neighbouring tests.
    """
    monkeypatch.setenv("VERDICT_AUTH_REQUIRED", "true")
    get_settings.cache_clear()
    import asyncio
    asyncio.run(_seed_verdict("epsilon", tenant_id="acme"))

    import app.main as app_main

    def _wrong_tenant(_request):
        return "globex"   # NOT acme

    monkeypatch.setattr(app_main, "_verified_tenant_id", _wrong_tenant)

    r = client.get("/verdict/epsilon", headers={"X-API-Key": "test-key"})
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# /audit/{alert_id}
# ---------------------------------------------------------------------------


class _FakeAudit:
    """Minimal AuditStore stand-in for tests."""

    def __init__(
        self,
        *,
        raw: dict[str, Any] | None = None,
        coercion: dict[str, Any] | None = None,
    ) -> None:
        self._raw = raw
        self._coercion = coercion

    async def get_bundle(
        self,
        alert_id: str,
        coercion_trace_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "alert_id": alert_id,
            "raw_payload": self._raw,
            "coercion": self._coercion if coercion_trace_id else None,
        }

    async def close(self) -> None:
        return None


def _attach_runtime(audit: _FakeAudit | None) -> None:
    from app._runtime_glue import RuntimeState

    app.state.runtime = RuntimeState(audit=audit)


def test_audit_requires_api_key(client) -> None:
    _attach_runtime(_FakeAudit(raw={"original": "json"}))
    r = client.get("/audit/some-id")
    assert r.status_code == 401


def test_audit_returns_503_when_audit_store_unconfigured(client) -> None:
    _attach_runtime(None)
    r = client.get("/audit/some-id", headers={"X-API-Key": "test-key"})
    assert r.status_code == 503


def test_audit_returns_404_when_no_data_present(client) -> None:
    _attach_runtime(_FakeAudit(raw=None, coercion=None))
    r = client.get("/audit/missing", headers={"X-API-Key": "test-key"})
    assert r.status_code == 404


def test_audit_returns_bundle_with_raw_payload(client) -> None:
    import asyncio
    asyncio.run(_seed_verdict("zeta"))
    _attach_runtime(_FakeAudit(raw={"original": "splunk-event-json"}))
    r = client.get("/audit/zeta", headers={"X-API-Key": "test-key"})
    assert r.status_code == 200
    body = r.json()
    assert body["alert_id"] == "zeta"
    assert body["raw_payload"] == {"original": "splunk-event-json"}
    # Coercion is None unless coercion_trace_id was set on the alert.
    assert body["coercion"] is None
    # Verdict summary is included for auditor convenience.
    assert body["verdict_summary"]["alert_id"] == "zeta"


def test_audit_returns_coercion_trace_when_alert_was_coerced(client) -> None:
    import asyncio

    from services.alert_persistence import get_alert_persistence

    async def _seed():
        persistence = get_alert_persistence()
        alert = _make_alert("eta")
        coerced = alert.model_copy(update={
            "coerced_by_llm": True,
            "coercion_trace_id": "trace-abc",
        })
        await persistence.put_alert(coerced)
        await persistence.put_verdict("eta", _make_verdict("eta"))

    asyncio.run(_seed())
    _attach_runtime(_FakeAudit(
        raw={"original": "json"},
        coercion={"prompt": "...", "model": "gpt-x", "response": {"title": "t"}},
    ))
    r = client.get("/audit/eta", headers={"X-API-Key": "test-key"})
    assert r.status_code == 200
    body = r.json()
    assert body["coercion"]["model"] == "gpt-x"
