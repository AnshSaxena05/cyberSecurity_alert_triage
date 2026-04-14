"""
POST /ingest/auto — expand nested envelopes, detect vendor shape, optionally coerce
unknown JSON with the fast LLM into flat fields the generic normaliser accepts.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from app.config import get_settings
from app.models import AlertSource, AutoIngestFlatView, NormalizedAlert
from components.alert_normalizer import (
    detect_source,
    expand_auto_ingest_payload,
    normalize_alert,
)

logger = structlog.get_logger(__name__)

_MAX_JSON_CHARS = 12_000


def _build_coerce_prompt(payload: dict[str, Any]) -> str:
    snippet = json.dumps(payload, default=str, indent=2)[:_MAX_JSON_CHARS]
    return f"""You are normalising an unknown security alert JSON into a flat summary for SOC triage.

Rules:
- Copy facts from the JSON only; do not invent IPs, domains, hashes, or MITRE T-codes that are not present in the input.
- If severity is unclear, use "medium".
- severity must be one of: low, medium, high, critical (lowercase).
- title: one short line (what the alert is about).
- description: 2–6 sentences summarising observable facts from the payload.

INPUT JSON:
{snippet}
"""


async def _llm_coerce_to_flat(payload: dict[str, Any]) -> AutoIngestFlatView | None:
    settings = get_settings()
    prompt = _build_coerce_prompt(payload)

    if settings.ollama_base_url:
        try:
            from langchain_ollama import ChatOllama

            llm = ChatOllama(
                model=settings.fast_model,
                base_url=settings.ollama_base_url,
                num_ctx=settings.ollama_num_ctx,
                keep_alive=settings.ollama_keep_alive,
                temperature=0,
            )
            return await llm.with_structured_output(
                AutoIngestFlatView,
                method="function_calling",
            ).ainvoke(prompt)
        except Exception as exc:
            logger.warning("auto_ingest_coerce_ollama_failed", error=str(exc))

    if settings.openai_api_key:
        try:
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI(
                model=settings.openai_model,
                api_key=settings.openai_api_key,
                temperature=0,
            )
            return await llm.with_structured_output(AutoIngestFlatView).ainvoke(prompt)
        except Exception as exc:
            logger.warning("auto_ingest_coerce_openai_failed", error=str(exc))

    return None


async def resolve_alert_for_auto_ingest(
    payload: dict[str, Any],
    *,
    use_llm: bool | None = None,
) -> NormalizedAlert:
    """
    Expand wrappers, run detect_source + normalize_alert, and if the source is still
    generic and LLM coercion is enabled, ask the fast model for a flat AutoIngestFlatView
    then normalise as GENERIC while preserving the original JSON on raw_payload.
    """
    settings = get_settings()
    if use_llm is None:
        use_llm = settings.auto_ingest_coerce_llm

    expanded = expand_auto_ingest_payload(payload)
    src = detect_source(expanded)

    if src is not AlertSource.GENERIC:
        alert = normalize_alert(src, expanded)
        return alert.model_copy(update={"raw_payload": payload})

    if use_llm:
        flat = await _llm_coerce_to_flat(expanded)
        if flat is not None:
            generic_payload = {
                "title": flat.title,
                "description": flat.description or flat.title,
                "severity": flat.severity,
            }
            if flat.hostname:
                generic_payload["hostname"] = flat.hostname
            if flat.mitre_technique:
                generic_payload["mitre_technique"] = flat.mitre_technique
            if flat.mitre_tactic:
                generic_payload["mitre_tactic"] = flat.mitre_tactic
            if flat.source_alert_id:
                generic_payload["id"] = flat.source_alert_id
            alert = normalize_alert(AlertSource.GENERIC, generic_payload)
            return alert.model_copy(update={"raw_payload": payload})

    alert = normalize_alert(AlertSource.GENERIC, expanded)
    return alert.model_copy(update={"raw_payload": payload})
