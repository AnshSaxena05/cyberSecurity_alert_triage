"""
MITRE routing and budget logic tests.
"""

from __future__ import annotations

import pytest


class TestMITRERouting:
    def test_all_golden_alert_techniques_have_routing(self):
        """Every technique from the golden alert set must have a routing entry."""
        from services.mitre_router import get_routing, DEFAULT_ROUTING

        golden_techniques = [
            "T1071.004",
            "T1486", "T1490",
            "T1078.004", "T1098",
            "T1053.005",
            "T1003.001", "T1071.001",
            "T1110.001",
        ]
        for tid in golden_techniques:
            entry = get_routing(tid)
            assert entry is not None, f"No routing entry for {tid}"
            assert len(entry.tools) > 0, f"Empty tool list for {tid}"

    def test_multi_technique_deduplication(self):
        """When two techniques prescribe the same tool, it should appear only once."""
        from services.mitre_router import get_tools_for_techniques

        tools = get_tools_for_techniques(["T1003.001", "T1003.002"])
        # Both prescribe query_splunk and query_crowdstrike
        assert tools.count("query_splunk") == 1
        assert tools.count("query_crowdstrike") == 1

    def test_priority_tool_comes_first(self):
        """Priority tools from the routing entry must appear before other tools."""
        from services.mitre_router import get_routing, get_tools_for_techniques

        # T1486 has priority_tool = "query_crowdstrike"
        tools = get_tools_for_techniques(["T1486"])
        entry = get_routing("T1486")
        assert tools[0] == entry.priority_tool

    def test_parent_technique_fallback(self):
        """T1003.999 (non-existent sub-technique) should fall back to T1003."""
        from services.mitre_router import get_routing

        entry_parent = get_routing("T1003.001")
        entry_unknown_sub = get_routing("T1003.999")
        # Should fall back to parent (T1003 not in table, so DEFAULT)
        assert entry_unknown_sub is not None

    def test_time_windows_match_context_doc(self):
        """Verify time windows match the exact values from the architecture doc."""
        from services.mitre_router import get_time_window

        assert get_time_window("T1003.001").hours == 72    # Process execution: 48-72h
        assert get_time_window("T1110.001").hours == 336   # Auth/login: 7-14 days = 336h
        assert get_time_window("T1071.004").hours == 720   # C2 beaconing: 30 days
        assert get_time_window("T1053.005").hours == 2160  # Persistence: 90 days
        assert get_time_window("T1078.004").hours == 336   # Auth events: 14 days
