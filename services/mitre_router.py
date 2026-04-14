"""
MITRE ATT&CK Technique → Tool Routing Table — Layer 2 (deterministic).

Maps T-codes to the ordered set of tools that MUST be called for that technique,
plus the time window to use for each signal type (Layer 6 from architecture doc).

This module is pure Python — no LLM involved. It executes in microseconds
and forms the deterministic backbone of the triage pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import NamedTuple


# ---------------------------------------------------------------------------
# Time Window Definitions (Layer 6)
# ---------------------------------------------------------------------------

class TimeWindow(NamedTuple):
    hours: int
    label: str


# Directly from context document Layer 6
PROCESS_EXECUTION_WINDOW = TimeWindow(hours=72, label="72h")
AUTH_LOGIN_WINDOW = TimeWindow(hours=336, label="14d")          # 14 days
LATERAL_MOVEMENT_WINDOW = TimeWindow(hours=48, label="48h")
C2_BEACONING_WINDOW = TimeWindow(hours=720, label="30d")        # 30 days
PERSISTENCE_WINDOW = TimeWindow(hours=2160, label="90d")        # 90 days
THREAT_INTEL_WINDOW = TimeWindow(hours=8760, label="12mo")      # 12 months
USER_BEHAVIOR_WINDOW = TimeWindow(hours=2160, label="90d")      # 90 days


# ---------------------------------------------------------------------------
# Routing Table Entry
# ---------------------------------------------------------------------------

@dataclass
class RoutingEntry:
    tools: list[str]                    # ordered tool names from registry
    time_window: TimeWindow
    parallel_burst: bool = True         # can all tools fire in parallel?
    priority_tool: str | None = None    # if set, this tool fires first alone


# ---------------------------------------------------------------------------
# TECHNIQUE_TO_TOOLS — primary routing table
# Direct expansion of context doc Layer 2 + additional techniques
# ---------------------------------------------------------------------------

TECHNIQUE_TO_TOOLS: dict[str, RoutingEntry] = {
    # -------------------------------------------------------- #
    # Credential Access
    # -------------------------------------------------------- #
    "T1003.001": RoutingEntry(  # LSASS Memory
        tools=["query_crowdstrike", "query_splunk", "lookup_threat_intel"],
        time_window=PROCESS_EXECUTION_WINDOW,
        priority_tool="query_crowdstrike",
    ),
    "T1003.002": RoutingEntry(  # SAM Database
        tools=["query_crowdstrike", "query_splunk"],
        time_window=PROCESS_EXECUTION_WINDOW,
    ),
    "T1003.003": RoutingEntry(  # NTDS
        tools=["query_crowdstrike", "query_splunk", "query_cmdb"],
        time_window=PROCESS_EXECUTION_WINDOW,
    ),
    "T1110.001": RoutingEntry(  # Brute Force: Password Guessing
        tools=["query_splunk", "query_cmdb"],
        time_window=AUTH_LOGIN_WINDOW,
    ),
    "T1110.003": RoutingEntry(  # Password Spraying
        tools=["query_splunk", "query_cmdb", "lookup_threat_intel"],
        time_window=AUTH_LOGIN_WINDOW,
    ),
    "T1555": RoutingEntry(      # Credentials from Password Stores
        tools=["query_crowdstrike", "query_splunk"],
        time_window=PROCESS_EXECUTION_WINDOW,
    ),

    # -------------------------------------------------------- #
    # Command and Control
    # -------------------------------------------------------- #
    "T1071.004": RoutingEntry(  # DNS Application Layer Protocol
        tools=["query_netflow", "query_dns_logs", "lookup_threat_intel"],
        time_window=C2_BEACONING_WINDOW,
    ),
    "T1071.001": RoutingEntry(  # Web Protocols (HTTP/S C2)
        tools=["query_netflow", "lookup_threat_intel", "query_splunk"],
        time_window=C2_BEACONING_WINDOW,
    ),
    "T1573": RoutingEntry(      # Encrypted Channel
        tools=["query_netflow", "lookup_threat_intel"],
        time_window=C2_BEACONING_WINDOW,
    ),
    "T1095": RoutingEntry(      # Non-Application Layer Protocol
        tools=["query_netflow", "lookup_threat_intel"],
        time_window=C2_BEACONING_WINDOW,
    ),

    # -------------------------------------------------------- #
    # Lateral Movement
    # -------------------------------------------------------- #
    "T1021.001": RoutingEntry(  # RDP
        tools=["query_netflow", "query_splunk", "query_cmdb"],
        time_window=LATERAL_MOVEMENT_WINDOW,
    ),
    "T1021.002": RoutingEntry(  # SMB/Windows Admin Shares
        tools=["query_netflow", "query_splunk", "query_crowdstrike"],
        time_window=LATERAL_MOVEMENT_WINDOW,
    ),
    "T1021.006": RoutingEntry(  # WinRM
        tools=["query_splunk", "query_crowdstrike"],
        time_window=LATERAL_MOVEMENT_WINDOW,
    ),

    # -------------------------------------------------------- #
    # Persistence
    # -------------------------------------------------------- #
    "T1053.005": RoutingEntry(  # Scheduled Task
        tools=["query_crowdstrike", "query_splunk"],
        time_window=PERSISTENCE_WINDOW,
    ),
    "T1547.001": RoutingEntry(  # Registry Run Keys
        tools=["query_crowdstrike", "query_splunk"],
        time_window=PERSISTENCE_WINDOW,
    ),
    "T1543.003": RoutingEntry(  # Windows Service
        tools=["query_crowdstrike", "query_splunk"],
        time_window=PERSISTENCE_WINDOW,
    ),

    # -------------------------------------------------------- #
    # Impact
    # -------------------------------------------------------- #
    "T1486": RoutingEntry(      # Data Encrypted for Impact (Ransomware)
        tools=["query_crowdstrike", "query_splunk", "query_backup_systems"],
        time_window=PROCESS_EXECUTION_WINDOW,
        parallel_burst=False,   # sequential: CrowdStrike first for process tree
        priority_tool="query_crowdstrike",
    ),
    "T1490": RoutingEntry(      # Inhibit System Recovery (shadow copy deletion)
        tools=["query_crowdstrike", "query_splunk", "query_backup_systems"],
        time_window=PROCESS_EXECUTION_WINDOW,
        priority_tool="query_crowdstrike",
    ),
    "T1489": RoutingEntry(      # Service Stop
        tools=["query_crowdstrike", "query_splunk"],
        time_window=PROCESS_EXECUTION_WINDOW,
    ),

    # -------------------------------------------------------- #
    # Privilege Escalation
    # -------------------------------------------------------- #
    "T1078.004": RoutingEntry(  # Valid Accounts: Cloud Accounts
        tools=["query_aws", "query_splunk", "lookup_threat_intel"],
        time_window=AUTH_LOGIN_WINDOW,
    ),
    "T1098": RoutingEntry(      # Account Manipulation
        tools=["query_splunk", "query_aws", "query_cmdb"],
        time_window=AUTH_LOGIN_WINDOW,
    ),
    "T1134": RoutingEntry(      # Access Token Manipulation
        tools=["query_crowdstrike", "query_splunk"],
        time_window=PROCESS_EXECUTION_WINDOW,
    ),

    # -------------------------------------------------------- #
    # Exfiltration
    # -------------------------------------------------------- #
    "T1048": RoutingEntry(      # Exfiltration Over Alternative Protocol
        tools=["query_netflow", "lookup_threat_intel", "query_splunk"],
        time_window=C2_BEACONING_WINDOW,
    ),
    "T1041": RoutingEntry(      # Exfiltration Over C2 Channel
        tools=["query_netflow", "lookup_threat_intel"],
        time_window=C2_BEACONING_WINDOW,
    ),

    # -------------------------------------------------------- #
    # Initial Access / Exploitation
    # -------------------------------------------------------- #
    "T1190": RoutingEntry(      # Exploit Public-Facing Application
        tools=["query_splunk", "lookup_vulncheck", "lookup_threat_intel", "query_cmdb"],
        time_window=PROCESS_EXECUTION_WINDOW,
    ),
    "T1203": RoutingEntry(      # Exploitation for Client Execution
        tools=["query_crowdstrike", "query_splunk", "lookup_vulncheck"],
        time_window=PROCESS_EXECUTION_WINDOW,
        priority_tool="query_crowdstrike",
    ),
    "T1210": RoutingEntry(      # Exploitation of Remote Services
        tools=["query_crowdstrike", "query_splunk", "lookup_vulncheck", "query_netflow"],
        time_window=LATERAL_MOVEMENT_WINDOW,
        priority_tool="query_crowdstrike",
    ),
    "T1211": RoutingEntry(      # Exploitation for Defense Evasion
        tools=["query_crowdstrike", "query_splunk", "lookup_vulncheck"],
        time_window=PROCESS_EXECUTION_WINDOW,
    ),

    # -------------------------------------------------------- #
    # Discovery
    # -------------------------------------------------------- #
    "T1082": RoutingEntry(      # System Information Discovery
        tools=["query_crowdstrike", "query_splunk"],
        time_window=PROCESS_EXECUTION_WINDOW,
    ),
    "T1083": RoutingEntry(      # File and Directory Discovery
        tools=["query_crowdstrike", "query_splunk"],
        time_window=PROCESS_EXECUTION_WINDOW,
    ),
    "T1046": RoutingEntry(      # Network Service Discovery / Port Scanning
        tools=["query_netflow", "query_splunk"],
        time_window=LATERAL_MOVEMENT_WINDOW,
    ),

    # -------------------------------------------------------- #
    # Defense Evasion
    # -------------------------------------------------------- #
    "T1055": RoutingEntry(      # Process Injection
        tools=["query_crowdstrike", "query_splunk"],
        time_window=PROCESS_EXECUTION_WINDOW,
    ),
    "T1562.001": RoutingEntry(  # Disable/Modify Tools
        tools=["query_crowdstrike", "query_splunk"],
        time_window=PROCESS_EXECUTION_WINDOW,
    ),
    "T1070.004": RoutingEntry(  # File Deletion
        tools=["query_crowdstrike", "query_splunk"],
        time_window=PROCESS_EXECUTION_WINDOW,
    ),

    # -------------------------------------------------------- #
    # Execution
    # -------------------------------------------------------- #
    "T1059.001": RoutingEntry(  # PowerShell
        tools=["query_crowdstrike", "query_splunk"],
        time_window=PROCESS_EXECUTION_WINDOW,
    ),
    "T1059.003": RoutingEntry(  # Windows Command Shell
        tools=["query_crowdstrike", "query_splunk"],
        time_window=PROCESS_EXECUTION_WINDOW,
    ),
}

# Fallback for unknown techniques
DEFAULT_ROUTING = RoutingEntry(
    tools=["query_splunk", "lookup_threat_intel", "query_cmdb"],
    time_window=PROCESS_EXECUTION_WINDOW,
)


# ---------------------------------------------------------------------------
# Budget table (Layer 5)
# ---------------------------------------------------------------------------

SEVERITY_BUDGET: dict[str, int] = {
    "LOW": 3,
    "MEDIUM": 5,
    "HIGH": 8,
    "CRITICAL": 15,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_routing(technique_id: str) -> RoutingEntry:
    """
    Return the routing entry for a MITRE technique ID.
    Strips sub-technique to try parent if specific match not found.
    """
    if technique_id in TECHNIQUE_TO_TOOLS:
        return TECHNIQUE_TO_TOOLS[technique_id]
    parent = technique_id.split(".")[0]
    if parent in TECHNIQUE_TO_TOOLS:
        return TECHNIQUE_TO_TOOLS[parent]
    return DEFAULT_ROUTING


def get_tools_for_techniques(technique_ids: list[str]) -> list[str]:
    """
    Given a list of MITRE technique IDs, return a deduplicated ordered list
    of tool names to execute, preserving priority-tool ordering.
    """
    seen: set[str] = set()
    ordered: list[str] = []

    # Priority tools from any technique come first
    for tid in technique_ids:
        entry = get_routing(tid)
        if entry.priority_tool and entry.priority_tool not in seen:
            ordered.append(entry.priority_tool)
            seen.add(entry.priority_tool)

    # Then all remaining tools
    for tid in technique_ids:
        entry = get_routing(tid)
        for tool in entry.tools:
            if tool not in seen:
                ordered.append(tool)
                seen.add(tool)

    return ordered


def get_time_window(technique_id: str) -> TimeWindow:
    """Return the recommended look-back time window for a technique."""
    return get_routing(technique_id).time_window


def get_budget(severity: str) -> int:
    """Return tool call budget for a severity level."""
    return SEVERITY_BUDGET.get(severity.upper(), 5)
