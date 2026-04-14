"""
FastAPI entry point — receives security alert webhooks and drives the triage pipeline.

Endpoints:
  POST /ingest/{source}     — receive raw alert from Splunk HEC, CrowdStrike, GuardDuty
  POST /ingest/auto         — auto-detect source from payload structure
  POST /ingest/batch        — bulk ingest (replay / SOAR)
  GET  /health              — liveness check
  GET  /metrics             — pipeline metrics snapshot
  GET  /verdict/{alert_id}  — stored verdict (memory or Redis when VERDICT_PERSISTENCE_ENABLED)
  GET  /jobs/{alert_id}     — queued | running | complete | failed (+ error when failed)
  GET  /stream/{alert_id}   — SSE job / verdict polling for long-running triage
  POST /feedback            — analyst agree/disagree (observability/feedback.py)
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any

import structlog
import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from fastapi.openapi.utils import get_openapi

from app.config import get_settings, Settings
from app.models import AlertSource, EscalationDecision, NormalizedAlert, TriageVerdict
from components.alert_normalizer import normalize_alert
from security.input_guard import (
    check_payload_size,
    sanitise_payload,
    validate_api_key,
)
from security.output_filter import scrub_verdict_for_log
from observability.tracer import get_tracer
from observability.cost_tracker import get_cost_tracker
from observability.feedback import get_feedback_store
from services.alert_persistence import get_alert_persistence

logger = structlog.get_logger(__name__)

app = FastAPI(
    title="SOC Triage Agent",
    description="Agentic SOC alert triage using LangGraph + Foundation-Sec-8B",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


def custom_openapi() -> dict[str, Any]:
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})["ApiKeyAuth"] = {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key",
        "description": "Must match API_KEY in server environment",
    }
    openapi_schema["security"] = [{"ApiKeyAuth": []}]
    health_get = openapi_schema.get("paths", {}).get("/health", {}).get("get")
    if isinstance(health_get, dict):
        health_get["security"] = []
    verdict_path = (openapi_schema.get("paths") or {}).get("/verdict/{alert_id}")
    if isinstance(verdict_path, dict):
        vget = verdict_path.get("get")
        if isinstance(vget, dict):
            vget["security"] = []
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi  # type: ignore[method-assign]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_pipeline_metrics: dict[str, Any] = {
    "alerts_received": 0,
    "verdicts_generated": 0,
    "errors": 0,
    "avg_latency_ms": 0.0,
}


# ---------------------------------------------------------------------------
# Startup / Shutdown
# ---------------------------------------------------------------------------


@app.on_event("startup")
async def startup_event() -> None:
    settings = get_settings()
    from observability.langfuse_client import connect_langfuse
    connect_langfuse(
        secret_key=settings.langfuse_secret_key,
        public_key=settings.langfuse_public_key,
        host=settings.langfuse_base_url,
        enabled=settings.langfuse_enabled,
    )
    logger.info(
        "soc_triage_agent_started",
        version=settings.app_version,
        deep_model=settings.deep_model,
        fast_model=settings.fast_model,
        cache_enabled=settings.cache_enabled,
        langfuse_enabled=settings.langfuse_enabled,
    )


@app.on_event("shutdown")
async def shutdown_event() -> None:
    from services.context_cache import get_cache
    from observability.langfuse_client import langfuse_flush

    await get_cache().close()
    await get_alert_persistence().close()
    langfuse_flush()
    logger.info("soc_triage_agent_stopped")


# ---------------------------------------------------------------------------
# Background triage task
# ---------------------------------------------------------------------------


async def _notify_triage_webhook(settings: Settings, alert_id: str, verdict: TriageVerdict) -> None:
    url = (settings.triage_complete_webhook_url or "").strip()
    if not url:
        return
    payload = {"alert_id": alert_id, "verdict": scrub_verdict_for_log(verdict.model_dump())}
    try:
        async with httpx.AsyncClient(timeout=30.0, verify=True) as client:
            await client.post(url, json=payload)
    except Exception as exc:
        logger.warning("triage_webhook_failed", alert_id=alert_id, error=str(exc))


async def _run_triage_background(
    alert: NormalizedAlert,
    tracer: Any,
    cost_tracker: Any,
) -> None:
    from services.triage_pipeline import run_triage

    persistence = get_alert_persistence()
    start = time.time()
    _pipeline_metrics["alerts_received"] += 1
    run_id = str(uuid.uuid4())
    await persistence.set_job(alert.alert_id, "running")

    try:
        with tracer.trace_alert(alert.alert_id, run_id=run_id):
            verdict = await run_triage(alert)

        elapsed_ms = int((time.time() - start) * 1000)
        await persistence.put_verdict(alert.alert_id, verdict)
        await persistence.set_job(alert.alert_id, "complete")
        _pipeline_metrics["verdicts_generated"] += 1

        n = _pipeline_metrics["verdicts_generated"]
        _pipeline_metrics["avg_latency_ms"] = (
            (_pipeline_metrics["avg_latency_ms"] * (n - 1) + elapsed_ms) / n
        )

        cost_tracker.record_triage(
            alert_id=alert.alert_id,
            tools_called=verdict.tools_called,
            elapsed_ms=elapsed_ms,
            severity=verdict.severity.value,
        )

        settings = get_settings()
        await _notify_triage_webhook(settings, alert.alert_id, verdict)

        logger.info(
            "triage_complete",
            alert_id=alert.alert_id,
            severity=verdict.severity.value,
            escalation=verdict.escalation.value,
            elapsed_ms=elapsed_ms,
            tools_used=verdict.total_tool_calls,
        )

    except Exception as exc:
        _pipeline_metrics["errors"] += 1
        await persistence.set_job(alert.alert_id, "failed", error=str(exc))
        logger.error("triage_pipeline_error", alert_id=alert.alert_id, error=str(exc))


# ---------------------------------------------------------------------------
# Ingestion endpoints
# ---------------------------------------------------------------------------
# Static paths (/ingest/auto, /ingest/batch) MUST be registered before
# /ingest/{source} so that "auto" and "batch" are not captured as source names.


class BatchIngestItem(BaseModel):
    source: str = Field(description="AlertSource value, e.g. splunk, crowdstrike, generic")
    payload: dict[str, Any]


class BatchIngestBody(BaseModel):
    items: list[BatchIngestItem] = Field(default_factory=list, max_length=500)


@app.post("/ingest/batch", status_code=status.HTTP_202_ACCEPTED)
async def ingest_batch(
    body: BatchIngestBody,
    request: Request,
    background_tasks: BackgroundTasks,
) -> dict[str, Any]:
    """Ingest many alerts in one request (golden replays, SOAR bulk)."""
    validate_api_key(request)
    persistence = get_alert_persistence()
    tracer = get_tracer()
    cost_tracker = get_cost_tracker()
    results: list[dict[str, Any]] = []

    for row in body.items:
        try:
            alert_source = AlertSource(row.source.lower())
        except ValueError:
            results.append(
                {
                    "ok": False,
                    "error": f"Unknown source '{row.source}'",
                }
            )
            continue
        try:
            payload = sanitise_payload(dict(row.payload))
            alert = normalize_alert(alert_source, payload)
        except Exception as exc:
            results.append({"ok": False, "error": str(exc)})
            continue
        await persistence.put_alert(alert)
        await persistence.set_job(alert.alert_id, "queued")
        background_tasks.add_task(_run_triage_background, alert, tracer, cost_tracker)
        results.append({"ok": True, "alert_id": alert.alert_id, "source": alert_source.value})

    accepted = sum(1 for r in results if r.get("ok"))
    return {"accepted": accepted, "total": len(body.items), "results": results}


@app.post("/ingest/auto", status_code=status.HTTP_202_ACCEPTED)
async def ingest_alert_auto(
    request: Request,
    background_tasks: BackgroundTasks,
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    """
    Auto-detect the alert source from payload structure and ingest.
    Useful for generic webhook receivers. Nested envelopes are unwrapped; ambiguous
    JSON can be flattened with the fast LLM when AUTO_INGEST_COERCE_LLM is true.
    """
    validate_api_key(request)
    raw_body = await request.body()
    check_payload_size(raw_body)
    payload = await request.json()
    payload = sanitise_payload(payload)

    try:
        from components.auto_ingest import resolve_alert_for_auto_ingest

        alert = await resolve_alert_for_auto_ingest(
            payload,
            use_llm=settings.auto_ingest_coerce_llm,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Normalisation failed: {exc}",
        )

    alert_source = alert.source
    persistence = get_alert_persistence()
    await persistence.put_alert(alert)
    await persistence.set_job(alert.alert_id, "queued")
    tracer = get_tracer()
    cost_tracker = get_cost_tracker()
    background_tasks.add_task(_run_triage_background, alert, tracer, cost_tracker)

    return {
        "alert_id": alert.alert_id,
        "detected_source": alert_source.value,
        "status": "queued",
    }


@app.post("/ingest/{source}", status_code=status.HTTP_202_ACCEPTED)
async def ingest_alert(
    source: str,
    request: Request,
    background_tasks: BackgroundTasks,
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    """
    Receive a raw alert payload from a known source.
    source must be one of: splunk, crowdstrike, aws_guardduty, sentinel, generic
    """
    validate_api_key(request)

    raw_body = await request.body()
    check_payload_size(raw_body)

    try:
        alert_source = AlertSource(source.lower())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown source '{source}'. Valid: {[s.value for s in AlertSource]}",
        )

    payload = await request.json()
    payload = sanitise_payload(payload)

    try:
        alert = normalize_alert(alert_source, payload)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to normalise alert: {exc}",
        )

    persistence = get_alert_persistence()
    await persistence.put_alert(alert)
    await persistence.set_job(alert.alert_id, "queued")
    tracer = get_tracer()
    cost_tracker = get_cost_tracker()
    background_tasks.add_task(_run_triage_background, alert, tracer, cost_tracker)

    logger.info(
        "alert_ingested",
        alert_id=alert.alert_id,
        source=source,
        severity=alert.severity.value,
        title=alert.title[:80],
    )
    return {
        "alert_id": alert.alert_id,
        "status": "queued",
        "message": "Alert accepted. Triage running asynchronously.",
    }


# ---------------------------------------------------------------------------
# Retrieval endpoints
# ---------------------------------------------------------------------------


@app.get("/verdict/{alert_id}")
async def get_verdict(alert_id: str) -> dict[str, Any]:
    """Retrieve the triage verdict for a previously ingested alert."""
    persistence = get_alert_persistence()
    verdict = await persistence.get_verdict(alert_id)
    if verdict:
        return {
            "alert_id": alert_id,
            "status": "complete",
            "verdict": scrub_verdict_for_log(verdict.model_dump()),
        }
    job = await persistence.get_job(alert_id)
    if job and job.get("status") == "failed":
        return {"alert_id": alert_id, "status": "failed", "error": job.get("error")}
    if await persistence.get_alert(alert_id):
        return {"alert_id": alert_id, "status": "processing"}
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"No verdict found for alert_id={alert_id}",
    )


@app.get("/alert/{alert_id}")
async def get_alert(alert_id: str, request: Request) -> dict[str, Any]:
    """Retrieve the normalised alert for an alert_id."""
    validate_api_key(request)
    persistence = get_alert_persistence()
    alert = await persistence.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert.model_dump()


@app.get("/jobs/{alert_id}")
async def get_job_status(alert_id: str, request: Request) -> dict[str, Any]:
    """Return triage job status for an alert (queued | running | complete | failed)."""
    validate_api_key(request)
    persistence = get_alert_persistence()
    job = await persistence.get_job(alert_id)
    if job:
        return {"alert_id": alert_id, **job}
    if await persistence.get_alert(alert_id) or await persistence.get_verdict(alert_id):
        return {"alert_id": alert_id, "status": "unknown"}
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")


@app.get("/stream/{alert_id}")
async def stream_triage_events(alert_id: str, request: Request) -> StreamingResponse:
    """Server-Sent Events: poll job status until verdict, failure, or timeout (~5 min)."""
    validate_api_key(request)

    # Frequent polls so clients see queued → running transitions; 1200 × 0.25s ≈ 5 min cap.
    _STREAM_POLL_SEC = 0.25
    _STREAM_MAX_TICKS = 1200

    async def event_gen() -> Any:
        persistence = get_alert_persistence()
        try:
            # Immediate line so proxies/clients flush; if triage already finished, next line is complete.
            yield (
                "data: "
                + json.dumps({"phase": "open", "alert_id": alert_id})
                + "\n\n"
            )
            for _ in range(_STREAM_MAX_TICKS):
                verdict = await persistence.get_verdict(alert_id)
                if verdict:
                    # mode="json" so datetimes/enums are JSON-serializable (plain model_dump breaks json.dumps)
                    payload = scrub_verdict_for_log(verdict.model_dump(mode="json"))
                    yield "data: " + json.dumps({"phase": "complete", "verdict": payload}) + "\n\n"
                    return
                job = await persistence.get_job(alert_id) or {}
                st = job.get("status")
                if st == "failed":
                    yield (
                        "data: "
                        + json.dumps({"phase": "failed", "error": job.get("error")})
                        + "\n\n"
                    )
                    return
                yield "data: " + json.dumps({"phase": st or "unknown", "alert_id": alert_id}) + "\n\n"
                await asyncio.sleep(_STREAM_POLL_SEC)
            yield "data: " + json.dumps({"phase": "timeout", "alert_id": alert_id}) + "\n\n"
        except Exception as exc:
            yield "data: " + json.dumps({"phase": "error", "error": str(exc)}) + "\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


class VerdictFeedbackBody(BaseModel):
    alert_id: str
    analyst_decision: EscalationDecision
    original_verdict: EscalationDecision | None = None
    comment: str = ""
    analyst_id: str = "anonymous"


@app.post("/feedback", status_code=status.HTTP_201_CREATED)
async def post_verdict_feedback(body: VerdictFeedbackBody, request: Request) -> dict[str, str]:
    """Record analyst feedback against a stored verdict (agreement inferred from decisions)."""
    validate_api_key(request)
    orig = body.original_verdict
    if orig is None:
        verdict = await get_alert_persistence().get_verdict(body.alert_id)
        if verdict is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No stored verdict for alert_id; pass original_verdict explicitly",
            )
        orig = verdict.escalation
    get_feedback_store().record(
        alert_id=body.alert_id,
        original_verdict=orig.value,
        analyst_decision=body.analyst_decision.value,
        comment=body.comment,
        analyst_id=body.analyst_id,
    )
    return {"status": "recorded"}


# ---------------------------------------------------------------------------
# Health and metrics
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "soc-triage-agent"}


@app.get("/metrics")
async def metrics(request: Request) -> dict[str, Any]:
    validate_api_key(request)
    sizes = await get_alert_persistence().store_sizes()
    return {
        "pipeline": _pipeline_metrics,
        "verdict_store_size": sizes.get("verdict_count"),
        "alert_store_size": sizes.get("alert_count"),
        "persistence_backend": sizes.get("backend"),
    }
