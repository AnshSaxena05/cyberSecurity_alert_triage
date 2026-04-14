"""
Entity extraction unit tests — validates heuristic and Pydantic schema enforcement.
"""

from __future__ import annotations

import pytest

from app.models import AlertSource, NormalizedAlert, Severity
from datetime import datetime


def _make_alert(**kwargs) -> NormalizedAlert:
    defaults = dict(
        source=AlertSource.GENERIC,
        title="Test Alert",
        description="Test description",
        severity=Severity.MEDIUM,
        timestamp=datetime.utcnow(),
    )
    defaults.update(kwargs)
    return NormalizedAlert(**defaults)


class TestHeuristicExtraction:
    def test_external_ip_captured_as_ioc(self):
        from components.entity_extractor import extract_entities_sync

        alert = _make_alert(
            description="Traffic from 10.0.0.1 to 8.8.8.8 and 185.220.101.45"
        )
        entities = extract_entities_sync(alert)
        ioc_values = [i.value for i in entities.iocs]
        # Internal IPs should be excluded
        assert "10.0.0.1" not in ioc_values
        # External IPs should be included
        assert "185.220.101.45" in ioc_values

    def test_sha256_hash_extracted(self):
        from components.entity_extractor import extract_entities_sync

        sha = "a" * 64
        alert = _make_alert(description=f"Process hash: {sha}")
        entities = extract_entities_sync(alert)
        hashes = [i.value for i in entities.iocs if i.type == "hash_sha256"]
        assert sha in hashes

    def test_mitre_technique_id_extracted(self):
        from components.entity_extractor import extract_entities_sync

        alert = _make_alert(
            description="Detected T1003.001 credential dump via LSASS memory access",
            mitre_technique="T1003.001",
        )
        entities = extract_entities_sync(alert)
        technique_ids = [t.technique_id for t in entities.techniques]
        assert "T1003.001" in technique_ids

    def test_suspicious_process_flagged(self):
        from app.models import ProcessActivity
        from components.entity_extractor import extract_entities_sync

        alert = _make_alert(
            description="mimikatz.exe executed",
            process=ProcessActivity(
                process_name="mimikatz.exe",
                process_path="C:\\Temp",
            ),
        )
        entities = extract_entities_sync(alert)
        if entities.processes:
            assert any(p.is_suspicious for p in entities.processes)

    def test_attack_chain_summary_populated(self):
        from components.entity_extractor import extract_entities_sync

        alert = _make_alert(title="Ransomware Pre-Stage", description="Files being encrypted")
        entities = extract_entities_sync(alert)
        assert len(entities.attack_chain_summary) > 0
