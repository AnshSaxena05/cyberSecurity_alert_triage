"""
Alert Normalizer — converts raw webhook payloads from Splunk HEC,
CrowdStrike Event Streams, and AWS GuardDuty into a canonical
OCSF-aligned NormalizedAlert.

Each source has its own `_parse_*` function. The public entry point
`normalize_alert(source, payload)` dispatches to the correct parser.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from app.models import (
    AlertSource,
    AttackContext,
    DetectionFindingSlice,
    EvidenceBundle,
    FindingInfo,
    NetworkActivity,
    NormalizedAlert,
    ObservableEntry,
    ProcessActivity,
    Severity,
    UserActivity,
)
from components.detection_finding_builder import attach_detection_finding


# ---------------------------------------------------------------------------
# Severity mapping helpers
# ---------------------------------------------------------------------------

_SPLUNK_SEV_MAP: dict[str | int, Severity] = {
    "informational": Severity.LOW,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    1: Severity.LOW,
    2: Severity.LOW,
    3: Severity.MEDIUM,
    4: Severity.HIGH,
    5: Severity.CRITICAL,
}

_CS_SEV_MAP: dict[str, Severity] = {
    "informational": Severity.LOW,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_GD_SEV_MAP: dict[str, Severity] = {
    # GuardDuty uses numeric 1.0–10.0
    # buckets: 1-3.9 = LOW, 4-6.9 = MEDIUM, 7-8.9 = HIGH, 9-10 = CRITICAL
}


def _guardduty_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _stable_alert_id(source: str, source_id: str) -> str:
    """Deterministic ID so duplicate webhooks produce the same alert_id."""
    return hashlib.sha256(f"{source}:{source_id}".encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Source-specific parsers
# ---------------------------------------------------------------------------


def _is_detection_finding_payload(payload: dict[str, Any]) -> bool:
    if payload.get("class_uid") == 2004:
        return True
    meta = payload.get("metadata")
    if isinstance(meta, dict) and meta.get("class_uid") == 2004:
        return True
    return False


_OCSF_SEVERITY_TO_ENUM: dict[int, Severity] = {
    1: Severity.LOW,
    2: Severity.LOW,
    3: Severity.MEDIUM,
    4: Severity.HIGH,
    5: Severity.CRITICAL,
    6: Severity.CRITICAL,
}


def _parse_ocsf_detection_finding_payload(payload: dict[str, Any]) -> NormalizedAlert:
    """Ingest a pre-built OCSF DetectionFinding (2004) thin JSON envelope."""
    fi_in = payload.get("finding_info") or {}
    title = str(fi_in.get("title") or payload.get("title") or "Detection Finding")
    desc = str(fi_in.get("desc") or fi_in.get("description") or payload.get("description", ""))[:4000]
    product_uid = str(fi_in.get("product_uid") or payload.get("product_uid") or "generic")
    sev_id = fi_in.get("severity_id")
    if isinstance(sev_id, int):
        sev = _OCSF_SEVERITY_TO_ENUM.get(sev_id, Severity.MEDIUM)
    else:
        sev = Severity.MEDIUM

    obs: list[ObservableEntry] = []
    for o in (payload.get("observables") or [])[:100]:
        if isinstance(o, dict) and o.get("value"):
            obs.append(
                ObservableEntry(
                    type=str(o.get("type", "Unknown"))[:128],
                    value=str(o["value"])[:2048],
                )
            )

    atk_in = payload.get("attacks") or {}
    tactic_name = None
    technique_uid = None
    if isinstance(atk_in.get("tactic"), dict):
        tactic_name = atk_in["tactic"].get("name")
    elif isinstance(atk_in.get("tactic_name"), str):
        tactic_name = atk_in.get("tactic_name")
    if isinstance(atk_in.get("technique"), dict):
        technique_uid = atk_in["technique"].get("uid")
    elif isinstance(atk_in.get("technique_uid"), str):
        technique_uid = atk_in.get("technique_uid")

    attacks = None
    if tactic_name or technique_uid:
        attacks = AttackContext(tactic_name=tactic_name, technique_uid=technique_uid)

    ev_in = payload.get("evidences") or {}
    qr = None
    if isinstance(ev_in, dict):
        qr = ev_in.get("query_result")
    evidences = EvidenceBundle(query_result=str(qr)[:8192] if qr else None)

    fi = FindingInfo(
        title=title[:512],
        desc=desc,
        product_uid=product_uid[:128],
        severity_id=sev_id if isinstance(sev_id, int) else None,
    )
    df = DetectionFindingSlice(
        schema_version=str(payload.get("schema_version", "1.0.0"))[:32],
        finding_info=fi,
        observables=obs,
        attacks=attacks,
        evidences=evidences if evidences.query_result else None,
    )

    ts_raw = payload.get("time") or payload.get("created_at") or payload.get("timestamp")
    try:
        ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00")) if ts_raw else datetime.now(timezone.utc)
    except Exception:
        ts = datetime.now(timezone.utc)

    src = AlertSource.GENERIC
    pl = product_uid.lower()
    if "splunk" in pl:
        src = AlertSource.SPLUNK
    elif "crowd" in pl or "falcon" in pl:
        src = AlertSource.CROWDSTRIKE
    elif "guardduty" in pl or "aws" in pl:
        src = AlertSource.AWS_GUARDDUTY

    aid = str(payload.get("finding_uid") or payload.get("activity_uid") or payload.get("id", ""))
    alert_id = _stable_alert_id("ocsf2004", aid or json.dumps(payload, sort_keys=True)[:200])

    hostname = None
    for o in obs:
        if "host" in o.type.lower():
            hostname = o.value
            break

    return NormalizedAlert(
        alert_id=alert_id,
        source=src,
        source_alert_id=aid or None,
        title=title[:512],
        description=desc,
        severity=sev,
        timestamp=ts,
        category_uid=2,
        class_uid=2004,
        hostname=hostname,
        mitre_tactic=tactic_name,
        mitre_technique=technique_uid,
        detection_finding=df,
        raw_payload=payload,
    )


def _parse_splunk(payload: dict[str, Any]) -> NormalizedAlert:
    """
    Handles both Splunk Alert Action payloads (result field) and
    Splunk HEC JSON events.
    """
    result = payload.get("result", payload)
    raw_sev = result.get("urgency", result.get("severity", "medium"))
    if isinstance(raw_sev, str):
        sev = _SPLUNK_SEV_MAP.get(raw_sev.lower(), Severity.MEDIUM)
    else:
        sev = _SPLUNK_SEV_MAP.get(raw_sev, Severity.MEDIUM)

    ts_raw = result.get("_time", result.get("timestamp"))
    try:
        ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
    except Exception:
        ts = datetime.now(timezone.utc)

    network = None
    if result.get("src_ip") or result.get("dest_ip"):
        network = NetworkActivity(
            src_ip=result.get("src_ip") or result.get("src"),
            dst_ip=result.get("dest_ip") or result.get("dest"),
            src_port=_int_or_none(result.get("src_port")),
            dst_port=_int_or_none(result.get("dest_port")),
            protocol=result.get("transport") or result.get("protocol"),
        )

    process = None
    if result.get("process_name") or result.get("process"):
        process = ProcessActivity(
            process_name=result.get("process_name") or result.get("process"),
            process_path=result.get("process_path"),
            process_id=_int_or_none(result.get("process_id") or result.get("pid")),
            parent_process_name=result.get("parent_process_name"),
            command_line=result.get("cmdline") or result.get("command_line"),
            hash_md5=result.get("md5") or result.get("file_hash"),
            hash_sha256=result.get("sha256"),
        )

    user = None
    if result.get("user") or result.get("src_user"):
        raw_user = result.get("user") or result.get("src_user", "")
        parts = raw_user.split("\\") if "\\" in raw_user else [None, raw_user]
        user = UserActivity(
            username=parts[-1],
            domain=parts[0] if len(parts) > 1 and parts[0] else None,
        )

    source_id = str(result.get("_cd", result.get("sid", result.get("search_name", ""))))

    return attach_detection_finding(
        NormalizedAlert(
            alert_id=_stable_alert_id("splunk", source_id),
            source=AlertSource.SPLUNK,
            source_alert_id=source_id,
            title=payload.get("search_name", result.get("source", "Splunk Alert")),
            description=result.get("message", result.get("_raw", json.dumps(result)[:500])),
            severity=sev,
            timestamp=ts,
            hostname=result.get("host") or result.get("dest_host") or result.get("ComputerName"),
            mitre_tactic=result.get("mitre_tactic"),
            mitre_technique=result.get("mitre_technique") or result.get("technique_id"),
            network=network,
            process=process,
            user=user,
            raw_payload=payload,
        )
    )


def _parse_crowdstrike(payload: dict[str, Any]) -> NormalizedAlert:
    """Handles CrowdStrike Falcon Event Stream detection payloads."""
    event = payload.get("event", payload)
    meta = payload.get("metadata", {})

    raw_sev = event.get("SeverityName", event.get("Severity", "medium"))
    if isinstance(raw_sev, str):
        sev = _CS_SEV_MAP.get(raw_sev.lower(), Severity.MEDIUM)
    else:
        # Numeric 1-5
        sev = _SPLUNK_SEV_MAP.get(int(raw_sev), Severity.MEDIUM)

    ts_epoch = event.get("ProcessStartTime") or meta.get("eventCreationTime", 0)
    try:
        ts = datetime.fromtimestamp(float(ts_epoch) / 1000, tz=timezone.utc)
    except Exception:
        ts = datetime.now(timezone.utc)

    process = ProcessActivity(
        process_name=event.get("FileName"),
        process_path=event.get("FilePath"),
        process_id=_int_or_none(event.get("TargetProcessId")),
        parent_process_name=event.get("ParentImageFileName"),
        command_line=event.get("CommandLine"),
        hash_sha256=event.get("SHA256HashData"),
        hash_md5=event.get("MD5HashData"),
    )

    user = None
    if event.get("UserName"):
        user = UserActivity(
            username=event["UserName"],
            domain=event.get("UserPrincipalName", "").split("@")[1]
            if "@" in event.get("UserPrincipalName", "")
            else None,
        )

    network = None
    if event.get("RemoteAddress"):
        network = NetworkActivity(
            dst_ip=event.get("RemoteAddress"),
            dst_port=_int_or_none(event.get("RemotePort")),
        )

    detection_id = event.get("DetectionId", meta.get("offset", ""))

    return attach_detection_finding(
        NormalizedAlert(
            alert_id=_stable_alert_id("crowdstrike", str(detection_id)),
            source=AlertSource.CROWDSTRIKE,
            source_alert_id=str(detection_id),
            title=event.get("DetectDescription") or event.get("Technique", "CrowdStrike Detection"),
            description=event.get("DetectDescription", "CrowdStrike Falcon detection"),
            severity=sev,
            timestamp=ts,
            hostname=event.get("ComputerName") or event.get("Hostname"),
            mitre_tactic=event.get("Tactic"),
            mitre_technique=event.get("Technique"),
            process=process,
            user=user,
            network=network,
            raw_payload=payload,
        )
    )


def _parse_guardduty(payload: dict[str, Any]) -> NormalizedAlert:
    """Handles AWS GuardDuty finding payloads (EventBridge format)."""
    detail = payload.get("detail", payload)
    sev_score = float(detail.get("severity", 5.0))
    sev = _guardduty_severity(sev_score)

    ts_raw = detail.get("updatedAt") or detail.get("createdAt") or payload.get("time", "")
    try:
        ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
    except Exception:
        ts = datetime.now(timezone.utc)

    service = detail.get("service", {})
    resource = detail.get("resource", {})
    instance = resource.get("instanceDetails", {})
    action = service.get("action", {})
    network_conn = action.get("networkConnectionAction", {})
    remote_ip = network_conn.get("remoteIpDetails", {})

    network = None
    if remote_ip.get("ipAddressV4"):
        network = NetworkActivity(
            src_ip=remote_ip.get("ipAddressV4"),
            dst_port=_int_or_none(network_conn.get("localPortDetails", {}).get("port")),
            protocol=network_conn.get("protocol"),
        )

    return attach_detection_finding(
        NormalizedAlert(
            alert_id=_stable_alert_id("guardduty", detail.get("id", "")),
            source=AlertSource.AWS_GUARDDUTY,
            source_alert_id=detail.get("id"),
            title=detail.get("title", "GuardDuty Finding"),
            description=detail.get("description", ""),
            severity=sev,
            timestamp=ts,
            hostname=instance.get("instanceId"),
            cloud_region=detail.get("region") or payload.get("region"),
            cloud_account_id=detail.get("accountId"),
            mitre_tactic=None,
            mitre_technique=detail.get("type"),  # GuardDuty type maps loosely to technique
            network=network,
            raw_payload=payload,
        )
    )


def _parse_generic(payload: dict[str, Any]) -> NormalizedAlert:
    """Fallback parser for generic JSON alert payloads."""
    raw_sev = str(payload.get("severity", payload.get("urgency", "medium"))).lower()
    sev = _SPLUNK_SEV_MAP.get(raw_sev, Severity.MEDIUM)
    ts_raw = payload.get("timestamp", payload.get("time", payload.get("created_at")))
    try:
        ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
    except Exception:
        ts = datetime.now(timezone.utc)

    return attach_detection_finding(
        NormalizedAlert(
            source=AlertSource.GENERIC,
            source_alert_id=str(payload.get("id", payload.get("alert_id", ""))),
            title=payload.get("title", payload.get("name", "Generic Alert")),
            description=payload.get("description", payload.get("message", json.dumps(payload)[:500])),
            severity=sev,
            timestamp=ts,
            hostname=payload.get("host", payload.get("hostname")),
            mitre_tactic=payload.get("mitre_tactic"),
            mitre_technique=payload.get("mitre_technique"),
            raw_payload=payload,
        )
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_PARSERS = {
    AlertSource.SPLUNK: _parse_splunk,
    AlertSource.CROWDSTRIKE: _parse_crowdstrike,
    AlertSource.AWS_GUARDDUTY: _parse_guardduty,
    AlertSource.GENERIC: _parse_generic,
}


def normalize_alert(source: AlertSource, payload: dict[str, Any]) -> NormalizedAlert:
    """
    Dispatch a raw alert payload to the correct source-specific parser
    and return a NormalizedAlert ready for the triage pipeline.
    """
    if _is_detection_finding_payload(payload):
        return _parse_ocsf_detection_finding_payload(payload)
    parser = _PARSERS.get(source, _parse_generic)
    return parser(payload)


def detect_source(payload: dict[str, Any]) -> AlertSource:
    """
    Attempt to infer the alert source from payload structure.
    Used when the source is not explicitly declared by the caller.
    """
    if _is_detection_finding_payload(payload):
        return AlertSource.GENERIC
    if "event" in payload and "DetectionId" in payload.get("event", {}):
        return AlertSource.CROWDSTRIKE
    # Unwrapped single-key {"event": {...}} leaves the Falcon detection object at top level
    if "DetectionId" in payload:
        return AlertSource.CROWDSTRIKE
    if "detail-type" in payload and "GuardDuty" in payload.get("detail-type", ""):
        return AlertSource.AWS_GUARDDUTY
    if "search_name" in payload or "result" in payload:
        return AlertSource.SPLUNK
    # Microsoft Sentinel-style incident (exported JSON often has properties.incidentNumber)
    if isinstance(payload.get("properties"), dict) and "incidentNumber" in payload["properties"]:
        return AlertSource.SENTINEL
    return AlertSource.GENERIC


def expand_auto_ingest_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Unwrap common webhook / SOAR envelopes so :func:`detect_source` sees inner vendor shapes.

    Handles single-key wrappers (``data``, ``alert``, ``body``, ``payload``), ``records[0]``,
    and improves detection when the outer object is generic but an inner dict is Splunk/CS/GD.
    """
    if not isinstance(payload, dict):
        return payload
    p: dict[str, Any] = dict(payload)
    if isinstance(p.get("records"), list) and p["records"] and isinstance(p["records"][0], dict):
        p = dict(p["records"][0])
    changed = True
    iterations = 0
    while changed and iterations < 6:
        iterations += 1
        changed = False
        if _is_detection_finding_payload(p):
            break
        outer_src = detect_source(p)
        for key in ("data", "alert", "body", "payload", "properties", "resource"):
            inner = p.get(key)
            if not isinstance(inner, dict):
                continue
            if _is_detection_finding_payload(inner):
                p = inner
                changed = True
                break
            inner_src = detect_source(inner)
            if inner_src is not AlertSource.GENERIC and outer_src is AlertSource.GENERIC:
                p = inner
                changed = True
                break
            if inner_src is not outer_src and inner_src is not AlertSource.GENERIC:
                p = inner
                changed = True
                break
        if not changed and len(p) == 1:
            sole_key, inner = next(iter(p.items()))
            if sole_key.lower() in (
                "alert",
                "data",
                "body",
                "payload",
                "event",
                "result",
                "resource",
            ) and isinstance(inner, dict):
                p = inner
                changed = True
    return p


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def _int_or_none(val: Any) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None
