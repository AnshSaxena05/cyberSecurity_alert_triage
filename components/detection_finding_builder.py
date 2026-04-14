"""
Build OCSF Findings Category UID 2 / DetectionFinding (Class UID 2004) LLM slice
from a NormalizedAlert — bounded observables, attacks, and evidence.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.models import (
    AttackContext,
    DetectionFindingSlice,
    EvidenceBundle,
    FindingInfo,
    NormalizedAlert,
    ObservableEntry,
    Severity,
)

if TYPE_CHECKING:
    pass

_MAX_DESC = 4000
_MAX_EVIDENCE = 8192


def _trunc(s: str | None, n: int) -> str:
    if not s:
        return ""
    s = str(s)
    return s if len(s) <= n else s[: n - 3] + "..."


_SEVERITY_TO_OCSF_ID: dict[Severity, int] = {
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


def build_detection_finding_slice(alert: NormalizedAlert) -> DetectionFindingSlice:
    """Project alert fields into a thin DetectionFinding-shaped envelope for LLMs."""
    fi = FindingInfo(
        title=_trunc(alert.title, 512),
        desc=_trunc(alert.description, _MAX_DESC),
        product_uid=alert.source.value,
        severity_id=_SEVERITY_TO_OCSF_ID.get(alert.severity),
    )
    obs: list[ObservableEntry] = []

    if alert.hostname:
        obs.append(ObservableEntry(type="Hostname", value=alert.hostname))
    if alert.asset_id:
        obs.append(ObservableEntry(type="Asset Identifier", value=str(alert.asset_id)))
    if alert.cloud_account_id:
        obs.append(ObservableEntry(type="Cloud Account", value=str(alert.cloud_account_id)))

    if alert.network:
        n = alert.network
        if n.src_ip:
            obs.append(ObservableEntry(type="IPv4 Address", value=n.src_ip))
        if n.dst_ip:
            obs.append(ObservableEntry(type="IPv4 Address", value=n.dst_ip))

    if alert.user and alert.user.username:
        u = f"{alert.user.domain}\\{alert.user.username}" if alert.user.domain else alert.user.username
        obs.append(ObservableEntry(type="User", value=u))

    if alert.process:
        p = alert.process
        if p.process_name:
            obs.append(ObservableEntry(type="Process Name", value=p.process_name))
        if p.hash_sha256:
            obs.append(ObservableEntry(type="SHA-256 Hash", value=p.hash_sha256))
        if p.hash_md5:
            obs.append(ObservableEntry(type="MD5 Hash", value=p.hash_md5))

    # Dedupe by (type, value)
    seen: set[tuple[str, str]] = set()
    deduped: list[ObservableEntry] = []
    for o in obs:
        key = (o.type, o.value)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(o)

    attacks: AttackContext | None = None
    if alert.mitre_tactic or alert.mitre_technique:
        attacks = AttackContext(
            tactic_name=alert.mitre_tactic,
            technique_uid=alert.mitre_technique,
        )

    evidence_text = ""
    if alert.process and alert.process.command_line:
        evidence_text = alert.process.command_line
    elif alert.description:
        evidence_text = alert.description
    evidences = EvidenceBundle(query_result=_trunc(evidence_text, _MAX_EVIDENCE) or None)

    return DetectionFindingSlice(
        schema_version="1.0.0",
        finding_info=fi,
        observables=deduped,
        attacks=attacks,
        evidences=evidences,
    )


def attach_detection_finding(alert: NormalizedAlert) -> NormalizedAlert:
    """Return alert with category_uid=2, class_uid=2004 and detection_finding populated."""
    df = build_detection_finding_slice(alert)
    return alert.model_copy(
        update={
            "category_uid": 2,
            "class_uid": 2004,
            "detection_finding": df,
        }
    )
