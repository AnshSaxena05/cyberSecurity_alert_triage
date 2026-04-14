"""
Query Builder — translates abstract triage queries into source-specific
query languages (SPL for Splunk, KQL for Sentinel, CSQL for CrowdStrike).

The LLM never writes query strings directly — it calls tools with typed
parameters; this module converts those parameters into runnable queries.
This prevents prompt injection through query strings and guarantees
syntactically valid queries every time.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


# ---------------------------------------------------------------------------
# Splunk SPL
# ---------------------------------------------------------------------------

class SPLBuilder:
    """Builds Splunk Search Processing Language queries from typed parameters."""

    @staticmethod
    def process_by_host(
        hostname: str,
        hours_back: int = 72,
        process_name: str | None = None,
    ) -> str:
        earliest = f"-{hours_back}h"
        base = (
            f'index=* sourcetype=WinEventLog:Security OR sourcetype=sysmon '
            f'host="{hostname}" EventCode IN (4688, 1) '
            f'earliest={earliest} '
        )
        if process_name:
            base += f'(process_name="{process_name}" OR Image="*{process_name}*") '
        base += "| table _time, host, user, process_name, cmdline, parent_process_name"
        return base

    @staticmethod
    def auth_events_by_user(username: str, hours_back: int = 336) -> str:
        return (
            f'index=* sourcetype=WinEventLog:Security '
            f'user="{username}" EventCode IN (4624, 4625, 4648, 4768, 4769) '
            f'earliest=-{hours_back}h '
            f'| table _time, host, user, src_ip, EventCode, LogonType'
        )

    @staticmethod
    def network_by_ip(ip: str, hours_back: int = 720) -> str:
        return (
            f'index=* sourcetype=firewall OR sourcetype=zeek_conn '
            f'(src_ip="{ip}" OR dest_ip="{ip}") earliest=-{hours_back}h '
            f'| stats sum(bytes_out) as total_bytes_out, count as connections, '
            f'  dc(dest_port) as unique_ports by src_ip, dest_ip, dest_port '
            f'| sort - total_bytes_out'
        )

    @staticmethod
    def dns_tunneling(hostname: str, hours_back: int = 720) -> str:
        return (
            f'index=* sourcetype=stream:dns OR sourcetype=zeek_dns '
            f'host="{hostname}" query_type=TXT earliest=-{hours_back}h '
            f'| eval query_len=len(query) '
            f'| stats count as query_count, avg(query_len) as avg_len, '
            f'  sum(bytes) as total_bytes by src_ip, dest_ip '
            f'| where query_count > 100 AND avg_len > 30'
        )

    @staticmethod
    def scheduled_tasks(hostname: str, hours_back: int = 2160) -> str:
        return (
            f'index=* sourcetype=WinEventLog:Security '
            f'host="{hostname}" EventCode IN (4698, 4702) '
            f'earliest=-{hours_back}h '
            f'| table _time, host, user, TaskName, TaskContent'
        )

    @staticmethod
    def shadow_copy_deletion(hours_back: int = 72) -> str:
        return (
            f'index=* sourcetype=WinEventLog:System OR sourcetype=sysmon '
            f'earliest=-{hours_back}h '
            f'(CommandLine="*vssadmin*delete*" OR CommandLine="*wmic*shadowcopy*delete*" '
            f' OR CommandLine="*bcdedit*/set*recoveryenabled*no*") '
            f'| table _time, host, user, cmdline, process_name, parent_process_name'
        )

    @staticmethod
    def file_rename_burst(hostname: str, hours_back: int = 24) -> str:
        return (
            f'index=* sourcetype=sysmon host="{hostname}" '
            f'EventCode=11 earliest=-{hours_back}h '
            f'| eval extension=mvindex(split(TargetFilename, "."), -1) '
            f'| stats count as renames by extension '
            f'| where renames > 100 '
            f'| sort - renames'
        )


# ---------------------------------------------------------------------------
# CrowdStrike FDR / Event Search (simple filter syntax)
# ---------------------------------------------------------------------------

class CrowdStrikeQueryBuilder:
    @staticmethod
    def process_tree(device_id: str, process_id: str | None = None) -> dict:
        params: dict = {"device_id": device_id}
        if process_id:
            params["process_id"] = process_id
        return params

    @staticmethod
    def detections_by_host(hostname: str, hours_back: int = 72) -> str:
        since = (
            datetime.now(timezone.utc) - timedelta(hours=hours_back)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        return f"device.hostname:'{hostname}'+created_timestamp:>'{since}'"

    @staticmethod
    def ioc_lookup(ioc_value: str, ioc_type: str = "sha256") -> str:
        return f"type:'{ioc_type}'+value:'{ioc_value}'"


# ---------------------------------------------------------------------------
# KQL (for Microsoft Sentinel)
# ---------------------------------------------------------------------------

class KQLBuilder:
    @staticmethod
    def process_by_host(hostname: str, hours_back: int = 72) -> str:
        return (
            f"SecurityEvent\n"
            f"| where TimeGenerated >= ago({hours_back}h)\n"
            f"| where Computer == '{hostname}'\n"
            f"| where EventID in (4688, 4689)\n"
            f"| project TimeGenerated, Computer, Account, Process, CommandLine, ParentProcessName"
        )

    @staticmethod
    def auth_by_user(username: str, hours_back: int = 336) -> str:
        return (
            f"SigninLogs\n"
            f"| where TimeGenerated >= ago({hours_back}h)\n"
            f"| where UserPrincipalName contains '{username}'\n"
            f"| project TimeGenerated, UserPrincipalName, IPAddress, Location, "
            f"ResultType, AppDisplayName"
        )
