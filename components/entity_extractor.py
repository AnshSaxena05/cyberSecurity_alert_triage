"""
Entity Extractor — Layer 1 of the Agentic SOC pipeline.

Uses ``with_structured_output`` for typed entities: on Ollama, ``method="function_calling"``
avoids GBNF grammar limits from the default ``json_schema`` path; OpenAI uses the default
structured output. The fast model handles this step; the deep model is reserved for ReAct.

Falls back to regex-based heuristic extraction if the LLM is unavailable
(e.g., Ollama not running during tests).
"""

from __future__ import annotations

import re
import structlog
from typing import Any

from langfuse import observe

from app.config import get_settings
from app.models import (
    ExtractedEntities,
    HostEntity,
    IOCEntity,
    NormalizedAlert,
    ProcessEntity,
    TechniqueEntity,
    UserEntity,
)

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns for heuristic fallback
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def _heuristic_extract(alert: NormalizedAlert) -> ExtractedEntities:
    """
    Deterministic regex-based entity extraction used as a fallback when
    the LLM is unavailable. Lower recall than LLM extraction but zero latency.
    """
    text = f"{alert.title} {alert.description}"
    raw = alert.raw_payload

    hosts: list[HostEntity] = []
    if alert.hostname:
        hosts.append(HostEntity(hostname=alert.hostname))

    users: list[UserEntity] = []
    if alert.user:
        users.append(
            UserEntity(
                username=alert.user.username or "unknown",
                domain=alert.user.domain,
                is_admin=alert.user.is_privileged,
            )
        )

    processes: list[ProcessEntity] = []
    if alert.process and alert.process.process_name:
        # Check both process name and command line — renamed binaries hide in the name
        name_suspicious_keywords = {"mimikatz", "psexec", "wce", "procdump", "lsass", "powershell"}
        cmdline_suspicious_keywords = {
            "sekurlsa", "logonpasswords", "privilege::debug",
            "lsadump", "kerberos::ptt", "pass-the-hash",
            "invoke-mimikatz", "invoke-bloodhound",
        }
        name_lower = alert.process.process_name.lower()
        cmdline_lower = (alert.process.command_line or "").lower()
        name_hit = any(k in name_lower for k in name_suspicious_keywords)
        cmd_hit = any(k in cmdline_lower for k in cmdline_suspicious_keywords)
        is_sus = name_hit or cmd_hit
        reason = None
        if cmd_hit:
            reason = "Mimikatz/credential dump command pattern in command line"
        elif name_hit:
            reason = "Known offensive tool name"
        processes.append(
            ProcessEntity(
                name=alert.process.process_name,
                path=alert.process.process_path,
                command_line=alert.process.command_line,
                hash_sha256=alert.process.hash_sha256,
                is_suspicious=is_sus,
                suspicion_reason=reason,
            )
        )

    techniques: list[TechniqueEntity] = []
    mitre_hits = _MITRE_RE.findall(text)
    if alert.mitre_technique:
        mitre_hits.insert(0, alert.mitre_technique)
    for tid in dict.fromkeys(mitre_hits):  # deduplicate, preserve order
        techniques.append(TechniqueEntity(technique_id=tid))

    iocs: list[IOCEntity] = []
    for ip in set(_IPV4_RE.findall(text)):
        if not ip.startswith(("10.", "192.168.", "172.")):
            iocs.append(IOCEntity(type="ip", value=ip))
    for h in set(_SHA256_RE.findall(text)):
        iocs.append(IOCEntity(type="hash_sha256", value=h))

    if alert.detection_finding:
        for ob in alert.detection_finding.observables:
            tl = ob.type.lower()
            if "ip" in tl or "ipv4" in tl or "ipv6" in tl:
                iocs.append(IOCEntity(type="ip", value=ob.value))
            elif "hash" in tl and "256" in tl:
                iocs.append(IOCEntity(type="hash_sha256", value=ob.value))
            elif "md5" in tl:
                iocs.append(IOCEntity(type="hash_md5", value=ob.value))
            elif "domain" in tl or "hostname" in tl or "host" in tl:
                iocs.append(IOCEntity(type="domain", value=ob.value))
            elif "url" in tl:
                iocs.append(IOCEntity(type="url", value=ob.value))
            elif "user" in tl:
                pass  # users list handled separately if needed

    return ExtractedEntities(
        hosts=hosts,
        users=users,
        processes=processes,
        techniques=techniques,
        iocs=iocs,
        attack_chain_summary=(
            f"{alert.title}: {alert.description[:200]}"
            if alert.description
            else alert.title
        ),
    )


def _build_extraction_prompt(alert: NormalizedAlert) -> str:
    return f"""You are a Tier 3 SOC analyst performing structured entity extraction.

Extract all security-relevant entities from the following alert.

ALERT TITLE: {alert.title}
ALERT DESCRIPTION: {alert.description}
SOURCE: {alert.source.value}
SEVERITY: {alert.severity.value}
HOSTNAME: {alert.hostname or 'unknown'}
MITRE TECHNIQUE (from source): {alert.mitre_technique or 'unknown'}
RAW DETAILS: {str(alert.raw_payload)[:1500]}

Extract:
- All hostnames and IP addresses (classify asset criticality if recognisable)
- All usernames and domains (flag admin/service accounts)
- All process names, paths, command lines, hashes (flag suspicious ones)
- All MITRE ATT&CK technique IDs present in the alert
- All IOCs: external IPs, file hashes, suspicious domains
- A 1-2 sentence attack chain summary

Be precise. Do not hallucinate entities not present in the alert data."""


@observe(name="extract_entities_llm", as_type="span")
async def extract_entities_llm(alert: NormalizedAlert) -> ExtractedEntities:
    """
    LLM-based entity extraction with structured output.
    Tries local Ollama first; falls back to OpenAI if Ollama is unavailable;
    falls back to heuristic regex extraction as last resort.
    """
    from observability.langfuse_client import get_langfuse_handler

    settings = get_settings()
    prompt = _build_extraction_prompt(alert)
    handler = get_langfuse_handler()
    callbacks_cfg: dict[str, Any] = {"callbacks": [handler]} if handler else {}

    # --- Attempt 1: Local Ollama ---
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
            result = await llm.with_structured_output(
                ExtractedEntities,
                method="function_calling",
            ).ainvoke(prompt, config=callbacks_cfg)
            logger.info("entity_extraction_complete", method="ollama", alert_id=alert.alert_id)
            return result
        except Exception as exc:
            logger.warning("entity_extraction_ollama_failed", error=str(exc), alert_id=alert.alert_id)

    # --- Attempt 2: OpenAI fallback ---
    if settings.openai_api_key:
        try:
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI(
                model=settings.openai_model,
                api_key=settings.openai_api_key,
                temperature=0,
            )
            result = await llm.with_structured_output(ExtractedEntities).ainvoke(
                prompt, config=callbacks_cfg,
            )
            logger.info("entity_extraction_complete", method="openai", alert_id=alert.alert_id)
            return result
        except Exception as exc:
            logger.warning("entity_extraction_openai_failed", error=str(exc), alert_id=alert.alert_id)

    # --- Attempt 3: Heuristic ---
    logger.warning("entity_extraction_all_llm_failed", alert_id=alert.alert_id, fallback="heuristic")
    return _heuristic_extract(alert)


def extract_entities_sync(alert: NormalizedAlert) -> ExtractedEntities:
    """Synchronous heuristic extraction — used for testing without Ollama."""
    return _heuristic_extract(alert)


@observe(name="extract_entities", as_type="span")
async def extract_entities(alert: NormalizedAlert, use_llm: bool = True) -> ExtractedEntities:
    """
    Primary entry point. Attempts LLM extraction; falls back to heuristic.
    Set use_llm=False for offline testing.
    """
    if not use_llm:
        return _heuristic_extract(alert)
    return await extract_entities_llm(alert)
