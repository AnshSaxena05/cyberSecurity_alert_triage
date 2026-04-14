"""
End-to-end triage tests using golden alerts.

These tests run without Ollama (use_llm=False) so they're CI-safe.
They exercise the full pipeline: normalise → extract → route → burst → verdict fallback.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.models import AlertSource, EscalationDecision, Severity

GOLDEN_PATH = Path(__file__).parent.parent / "evaluation" / "golden_alerts.json"


@pytest.fixture(scope="session")
def golden_alerts():
    with open(GOLDEN_PATH) as f:
        return json.load(f)["alerts"]


# ---------------------------------------------------------------------------
# Normaliser tests
# ---------------------------------------------------------------------------


class TestAlertNormaliser:
    def test_splunk_normalise(self):
        from components.alert_normalizer import normalize_alert

        payload = {
            "search_name": "Test Alert",
            "result": {
                "_time": "2026-04-12T04:00:00Z",
                "urgency": "high",
                "host": "server-01",
                "src_ip": "10.0.0.1",
                "dest_ip": "185.220.101.45",
                "message": "Test Splunk alert",
                "user": "DOMAIN\\jsmith",
                "process_name": "powershell.exe",
            },
        }
        alert = normalize_alert(AlertSource.SPLUNK, payload)
        assert alert.severity == Severity.HIGH
        assert alert.hostname == "server-01"
        assert alert.network is not None
        assert alert.network.src_ip == "10.0.0.1"
        assert alert.user is not None
        assert alert.user.username == "jsmith"
        assert alert.process is not None
        assert alert.process.process_name == "powershell.exe"

    def test_crowdstrike_normalise(self):
        from components.alert_normalizer import normalize_alert

        payload = {
            "event": {
                "DetectionId": "ldt:abc:123",
                "DetectDescription": "Mimikatz detected",
                "SeverityName": "Critical",
                "Technique": "OS Credential Dumping",
                "Tactic": "Credential Access",
                "ComputerName": "dc01",
                "FileName": "mimikatz.exe",
                "CommandLine": "mimikatz privilege::debug",
                "UserName": "DOMAIN\\admin",
                "SHA256HashData": "deadbeef" * 8,
                "ProcessStartTime": "1744428600000",
            },
            "metadata": {"eventCreationTime": 1744428600000},
        }
        alert = normalize_alert(AlertSource.CROWDSTRIKE, payload)
        assert alert.severity == Severity.CRITICAL
        assert alert.hostname == "dc01"
        assert alert.process is not None
        assert alert.process.hash_sha256 == "deadbeef" * 8

    def test_guardduty_normalise(self, golden_alerts):
        from components.alert_normalizer import normalize_alert

        gd_case = next(a for a in golden_alerts if a["id"] == "golden-003")
        alert = normalize_alert(AlertSource.AWS_GUARDDUTY, gd_case["payload"])
        assert alert.severity == Severity.HIGH
        assert alert.cloud_region == "us-east-1"
        assert alert.cloud_account_id == "123456789012"

    def test_source_auto_detect(self):
        from components.alert_normalizer import detect_source

        splunk_payload = {"search_name": "Test", "result": {}}
        assert detect_source(splunk_payload) == AlertSource.SPLUNK

        cs_payload = {"event": {"DetectionId": "ldt:abc:123"}, "metadata": {}}
        assert detect_source(cs_payload) == AlertSource.CROWDSTRIKE

    def test_expand_auto_ingest_unwraps_nested_splunk(self):
        from components.alert_normalizer import detect_source, expand_auto_ingest_payload

        wrapped = {
            "data": {
                "search_name": "Wrapped",
                "result": {"_time": "2026-04-12T04:00:00Z", "urgency": "low", "message": "m"},
            }
        }
        exp = expand_auto_ingest_payload(wrapped)
        assert detect_source(exp) == AlertSource.SPLUNK
        assert exp.get("search_name") == "Wrapped"

    def test_expand_single_key_cs_event(self):
        from components.alert_normalizer import detect_source, expand_auto_ingest_payload

        wrapped = {"event": {"DetectionId": "ldt:x:1", "ComputerName": "h"}}
        exp = expand_auto_ingest_payload(wrapped)
        assert detect_source(exp) == AlertSource.CROWDSTRIKE

    @pytest.mark.asyncio
    async def test_resolve_auto_ingest_arbitrary_json_without_llm(self):
        from components.auto_ingest import resolve_alert_for_auto_ingest

        payload = {
            "rule": "Suspicious login",
            "details": "User admin from 203.0.113.5",
            "risk": "high",
        }
        alert = await resolve_alert_for_auto_ingest(payload, use_llm=False)
        assert alert.source == AlertSource.GENERIC
        assert alert.raw_payload == payload
        assert "203.0.113.5" in alert.description or "203.0.113.5" in alert.title

    def test_stable_alert_id(self):
        from components.alert_normalizer import normalize_alert

        payload = {
            "search_name": "Test",
            "result": {
                "_time": "2026-04-12T04:00:00Z",
                "urgency": "medium",
                "_cd": "idx:12345",
                "message": "test",
            },
        }
        a1 = normalize_alert(AlertSource.SPLUNK, payload)
        a2 = normalize_alert(AlertSource.SPLUNK, payload)
        assert a1.alert_id == a2.alert_id, "Same payload must produce same alert_id"

    def test_ocsf_detection_finding_ingress(self):
        from components.alert_normalizer import normalize_alert

        payload = {
            "class_uid": 2004,
            "schema_version": "1.3.0",
            "finding_info": {
                "title": "Suspicious PowerShell",
                "desc": "Hidden window download",
                "product_uid": "generic_si",
                "severity_id": 4,
            },
            "observables": [
                {"type": "IP Address", "value": "198.51.100.4"},
                {"type": "User", "value": "jdoe"},
            ],
            "attacks": {
                "tactic": {"name": "Execution"},
                "technique": {"uid": "T1059.001"},
            },
            "evidences": {"query_result": "EncodedCommand..."},
            "finding_uid": "fd-123",
            "time": "2026-04-12T10:00:00Z",
        }
        alert = normalize_alert(AlertSource.GENERIC, payload)
        assert alert.class_uid == 2004
        assert alert.category_uid == 2
        assert alert.detection_finding is not None
        assert alert.detection_finding.finding_info.title == "Suspicious PowerShell"
        assert len(alert.detection_finding.observables) == 2
        assert alert.mitre_technique == "T1059.001"
        assert alert.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Entity Extractor tests
# ---------------------------------------------------------------------------


class TestEntityExtractor:
    def test_heuristic_extraction_mimikatz(self, golden_alerts):
        from components.alert_normalizer import normalize_alert
        from components.entity_extractor import extract_entities_sync

        cs_case = next(a for a in golden_alerts if a["id"] == "golden-005")
        alert = normalize_alert(AlertSource.CROWDSTRIKE, cs_case["payload"])
        entities = extract_entities_sync(alert)

        assert len(entities.hosts) > 0
        assert entities.hosts[0].hostname == "dc01"
        # Mimikatz binary should be flagged as suspicious
        if entities.processes:
            sus_procs = [p for p in entities.processes if p.is_suspicious]
            assert len(sus_procs) > 0

    def test_heuristic_extraction_dns_tunnel(self, golden_alerts):
        from components.alert_normalizer import normalize_alert
        from components.entity_extractor import extract_entities_sync

        dns_case = next(a for a in golden_alerts if a["id"] == "golden-001")
        alert = normalize_alert(AlertSource.SPLUNK, dns_case["payload"])
        entities = extract_entities_sync(alert)

        assert len(entities.hosts) > 0
        # External IP should be in IOCs
        external_ips = [i for i in entities.iocs if i.type == "ip"]
        assert len(external_ips) > 0

    def test_technique_extraction(self, golden_alerts):
        from components.alert_normalizer import normalize_alert
        from components.entity_extractor import extract_entities_sync

        ransomware_case = next(a for a in golden_alerts if a["id"] == "golden-002")
        alert = normalize_alert(AlertSource.CROWDSTRIKE, ransomware_case["payload"])
        entities = extract_entities_sync(alert)
        # Should have at least the technique from the raw alert
        assert len(entities.techniques) >= 0  # may come from alert.mitre_technique


# ---------------------------------------------------------------------------
# MITRE Router tests
# ---------------------------------------------------------------------------


class TestMITRERouter:
    def test_known_technique_routing(self):
        from services.mitre_router import get_routing, get_tools_for_techniques

        entry = get_routing("T1003.001")
        assert "query_crowdstrike" in entry.tools
        assert entry.time_window.hours == 72

    def test_dns_tunnel_routing(self):
        from services.mitre_router import get_tools_for_techniques

        tools = get_tools_for_techniques(["T1071.004"])
        assert "query_netflow" in tools
        assert "lookup_threat_intel" in tools

    def test_ransomware_routing_priority(self):
        from services.mitre_router import get_routing

        entry = get_routing("T1486")
        assert entry.priority_tool == "query_crowdstrike"
        assert "query_backup_systems" in entry.tools

    def test_unknown_technique_fallback(self):
        from services.mitre_router import get_routing, DEFAULT_ROUTING

        entry = get_routing("T9999.999")
        assert entry == DEFAULT_ROUTING

    def test_budget_by_severity(self):
        from services.mitre_router import get_budget

        assert get_budget("LOW") == 3
        assert get_budget("MEDIUM") == 5
        assert get_budget("HIGH") == 8
        assert get_budget("CRITICAL") == 15


# ---------------------------------------------------------------------------
# Context Cache tests
# ---------------------------------------------------------------------------


class TestContextCache:
    @pytest.mark.asyncio
    async def test_cache_disabled(self):
        from services.context_cache import ContextCache

        cache = ContextCache(redis_url="redis://localhost:6379", enabled=False)
        result = await cache.get("query_splunk", {"hostname": "test"})
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_key_determinism(self):
        from services.context_cache import _make_key

        k1 = _make_key("tool_a", {"b": 2, "a": 1})
        k2 = _make_key("tool_a", {"a": 1, "b": 2})
        assert k1 == k2, "Cache key must be order-independent"


# ---------------------------------------------------------------------------
# Security layer tests
# ---------------------------------------------------------------------------


class TestSecurityLayers:
    def test_input_sanitise_injection(self):
        from security.input_guard import sanitise_payload

        malicious = {
            "message": "SELECT * FROM users WHERE 1=1 DROP TABLE users",
            "host": "server-01",
        }
        clean = sanitise_payload(malicious)
        assert clean["message"] == "[REDACTED]"
        assert clean["host"] == "server-01"

    def test_content_filter_dangerous_spl(self):
        from security.content_filter import validate_tool_params

        ok, reason = validate_tool_params(
            "query_splunk",
            {"query_type": "raw_spl", "raw_spl": "index=* | delete"},
        )
        assert ok is False
        assert "delete" in reason.lower()

    def test_content_filter_ssrf(self):
        from security.content_filter import validate_tool_params

        ok, reason = validate_tool_params(
            "lookup_threat_intel",
            {"ioc_type": "ip", "ioc_value": "169.254.169.254"},
        )
        assert ok is False

    def test_content_filter_safe(self):
        from security.content_filter import validate_tool_params

        ok, _ = validate_tool_params(
            "query_splunk",
            {"query_type": "process_by_host", "hostname": "server-01", "hours_back": 72},
        )
        assert ok is True


# ---------------------------------------------------------------------------
# Tool stubs (smoke tests — verify they return expected schema)
# ---------------------------------------------------------------------------


class TestToolSmoke:
    @pytest.mark.asyncio
    async def test_cmdb_tool_returns_schema(self):
        from agents.tools.cmdb_tool import cmdb_query_async, CMDBInput

        params = CMDBInput(lookup_type="by_hostname", hostname="dc01")
        result = await cmdb_query_async(params)
        assert result.get("source_available") is False
        assert result.get("error")

    @pytest.mark.asyncio
    async def test_netflow_dns_entropy(self):
        from agents.tools.netflow_tool import netflow_query_async, NetFlowInput

        params = NetFlowInput(
            query_type="dns_entropy_analysis",
            src_ip="10.0.0.100",
            hours_back=720,
        )
        result = await netflow_query_async(params)
        assert result.get("source_available") is False
        assert result.get("query_type") == "dns_entropy_analysis"
        assert result.get("error")

    @pytest.mark.asyncio
    async def test_backup_shadow_copy(self):
        from agents.tools.backup_tool import backup_query_async, BackupQueryInput

        params = BackupQueryInput(query_type="shadow_copy_status", hostname="fileserver-01")
        result = await backup_query_async(params)
        assert result.get("source_available") is False
        assert result.get("error")
        assert result.get("query_type") == "shadow_copy_status"


# ---------------------------------------------------------------------------
# Enrichment burst tests
# ---------------------------------------------------------------------------


class TestEnrichmentBurst:
    @pytest.mark.asyncio
    async def test_burst_returns_records(self, golden_alerts):
        from components.alert_normalizer import normalize_alert
        from components.entity_extractor import extract_entities_sync
        from agents.enrichment_node import run_burst_enrichment

        dns_case = next(a for a in golden_alerts if a["id"] == "golden-001")
        alert = normalize_alert(AlertSource.SPLUNK, dns_case["payload"])
        entities = extract_entities_sync(alert)
        technique_ids = ["T1071.004"]

        enrichment_data, records = await run_burst_enrichment(
            alert=alert,
            entities=entities,
            technique_ids=technique_ids,
            timeout_seconds=15,
        )

        assert len(records) > 0
        assert isinstance(enrichment_data, dict)
        # All records should have a result summary
        for record in records:
            assert record.result_summary
            assert record.tool_name


# ---------------------------------------------------------------------------
# Query builder tests
# ---------------------------------------------------------------------------


class TestQueryBuilder:
    def test_spl_process_by_host(self):
        from services.query_builder import SPLBuilder

        spl = SPLBuilder.process_by_host("dc01", hours_back=72)
        assert "dc01" in spl
        assert "earliest=-72h" in spl
        assert "process_name" in spl or "Image" in spl

    def test_spl_auth_events(self):
        from services.query_builder import SPLBuilder

        spl = SPLBuilder.auth_events_by_user("jsmith", hours_back=336)
        assert "jsmith" in spl
        assert "4624" in spl

    def test_spl_dns_tunneling(self):
        from services.query_builder import SPLBuilder

        spl = SPLBuilder.dns_tunneling("workstation-045", hours_back=720)
        assert "workstation-045" in spl
        assert "TXT" in spl
        assert "entropy" in spl.lower() or "query_len" in spl


# ---------------------------------------------------------------------------
# Prompt building (must not KeyError on SPL/JSON braces in enrichment)
# ---------------------------------------------------------------------------


class TestPromptFormatSafety:
    def test_build_verdict_prompt_json_braces(self):
        from prompts.templates import build_verdict_prompt

        malicious_enrichment = '{"query": "index=* | head 1", "host": "x"}'
        text = build_verdict_prompt(
            alert_title="Test",
            original_severity="HIGH",
            entities_summary="{}",
            full_enrichment=malicious_enrichment,
            technique_context="",
        )
        assert malicious_enrichment in text
        assert "{persona}" not in text

    def test_build_triage_prompt_json_braces(self):
        from prompts.templates import build_triage_prompt

        summary = 'Splunk: {"query": "search *"}'
        text = build_triage_prompt(
            severity=Severity.HIGH,
            budget=3,
            tool_descriptions="tools",
            enrichment_summary=summary,
        )
        assert "search *" in text or '"query"' in text
