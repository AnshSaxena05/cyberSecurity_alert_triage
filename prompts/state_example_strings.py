"""
Pipeline state shape examples for SUB-2 (route_tools, burst_enrichment).

Imported by prompts/templates.py into PIPELINE_STATE_SUB_AGENT_SYSTEM_PROMPT.
Not executed at runtime by the triage graph — documentation / LLM handoff only.
"""

ROUTE_TOOLS_STATE_EXAMPLE = """
Example **`route_tools_node`** state update (severity HIGH → budget 8):

```json
{"tool_budget": 8, "phase": "burst"}
```

`tool_budget` comes from `get_budget(severity)` in `services/mitre_router.py` (`SEVERITY_BUDGET`: LOW=3, MEDIUM=5, HIGH=8, CRITICAL=15). `phase` becomes `"burst"` before `burst_enrichment_node` runs.
"""

# Post-burst shape: enrichment_data keys are compressed strings from compress_tool_result (enrichment_node.py).
# external_api_per_tool documents vendor HTTP/API surfaces (implementation in agents/tools/*.py).
BURST_ENRICHMENT_STATE_EXAMPLE = r"""
Example **`burst_enrichment_node`** state update (after `run_burst_enrichment` in `agents/enrichment_node.py`). **`enrichment_data`** maps `tool_name` → **compressed summary string** (not raw API JSON). Each tool execution uses `_execute_single_tool` → registry async fn from `_TOOL_REGISTRY` + params from `_PARAM_BUILDERS`.

**External API binding (which backend each tool calls)** — use this when describing burst calls:

| `tool_name` | External API / transport | Source module |
|-------------|--------------------------|---------------|
| `query_splunk` | Splunk REST: `POST {SPLUNK_SCHEME}://{SPLUNK_HOST}:{SPLUNK_PORT}/services/search/jobs`, then `GET .../jobs/{sid}`, `GET .../jobs/{sid}/results` | `agents/tools/splunk_tool.py` |
| `query_crowdstrike` | Falcon API: `POST {CROWDSTRIKE_BASE_URL}/oauth2/token`, then e.g. `/detects/queries/detects/v1`, `/alerts/queries/alerts/v2`, etc. | `agents/tools/crowdstrike_tool.py` |
| `lookup_threat_intel` | VirusTotal `https://www.virustotal.com/api/v3/...`, AbuseIPDB `https://api.abuseipdb.com/api/v2/check`, OTX `https://otx.alienvault.com/api/v1/...` | `agents/tools/threat_intel_tool.py` |
| `query_aws` | AWS SDK (`boto3`) — CloudTrail / GuardDuty regional endpoints | `agents/tools/aws_tool.py` |
| `query_cmdb` | ServiceNow: `GET {SERVICENOW_INSTANCE_URL}/api/now/table/cmdb_ci`; optional `POST .../oauth_token.do` | `agents/tools/cmdb_tool.py` |
| `query_netflow` / `query_dns_logs` | Configured `NDR_FLOW_API_URL` (`POST` JSON body) — same `netflow_query_async` | `agents/tools/netflow_tool.py` |
| `query_backup_systems` | Configured `BACKUP_API_URL` (`POST` JSON body) | `agents/tools/backup_tool.py` |
| `lookup_vulncheck` | `GET https://api.vulncheck.com/v3/index/vulncheck-nvd2?cve=...` | `agents/tools/vulncheck_tool.py` |

Illustrative full state shape (values anonymised; **`tool_budget`** is reduced by the number of burst calls executed):

```json
{
  "enrichment_data": {
    "query_splunk": "[query_splunk] ERROR: [Errno 8] nodename nor servname provided, or not known",
    "lookup_threat_intel": "[ThreatIntel] IOC=203.0.113.50 Verdict=SUSPICIOUS — VT: 1/94 engines flagged | AbuseIPDB: 0% confidence, 12 reports | OTX: 1 threat pulses",
    "query_cmdb": "[query_cmdb] ERROR: ServiceNow CMDB request failed (HTTP error, timeout, or invalid credentials). Check instance URL, user ACLs on cmdb_ci, and logs."
  },
  "tool_records": [
    {
      "tool_name": "query_splunk",
      "external_api_hint": "Splunk REST jobs API — POST {base}/services/search/jobs (see splunk_tool.py)",
      "input_params": {
        "query_type": "process_by_host",
        "hostname": "web-prod-07",
        "hours_back": 72
      },
      "result_summary": "[query_splunk] ERROR: [Errno 8] nodename nor servname provided, or not known",
      "raw_result": {
        "source_available": false,
        "error": "[Errno 8] nodename nor servname provided, or not known",
        "results": []
      },
      "source_available": false,
      "latency_ms": 35,
      "error": "[Errno 8] nodename nor servname provided, or not known"
    },
    {
      "tool_name": "lookup_threat_intel",
      "external_api_hint": "Parallel GETs to VirusTotal api/v3, AbuseIPDB api/v2/check, OTX api/v1 (threat_intel_tool.py)",
      "input_params": {
        "ioc_type": "ip",
        "ioc_value": "203.0.113.50"
      },
      "result_summary": "[ThreatIntel] IOC=203.0.113.50 Verdict=SUSPICIOUS — ...",
      "raw_result": { "ioc": "203.0.113.50", "verdict": "SUSPICIOUS" },
      "source_available": true,
      "latency_ms": 608,
      "error": null
    },
    {
      "tool_name": "query_cmdb",
      "external_api_hint": "ServiceNow Table API — GET {instance}/api/now/table/cmdb_ci (cmdb_tool.py)",
      "input_params": {
        "lookup_type": "by_hostname",
        "hostname": "web-prod-07"
      },
      "result_summary": "[query_cmdb] ERROR: ServiceNow CMDB request failed ...",
      "raw_result": {
        "source_available": false,
        "source": "cmdb",
        "error": "ServiceNow CMDB request failed (HTTP error, timeout, or invalid credentials). ..."
      },
      "source_available": false,
      "latency_ms": 1092,
      "error": "ServiceNow CMDB request failed ..."
    }
  ],
  "tools_called": ["query_splunk", "lookup_threat_intel", "query_cmdb"],
  "tool_budget": 5,
  "messages": [
    {
      "type": "human",
      "content": "ALERT: Suspicious curl outbound to pastebin-like host\\nSEVERITY: HIGH\\n...\\nINITIAL ENRICHMENT (parallel burst):\\n  • query_splunk: ...\\n  • lookup_threat_intel: ...\\n  • query_cmdb: ...\\n\\nTool budget remaining: 5. Decide if further investigation is needed."
    }
  ],
  "phase": "react"
}
```

Notes: Real **`ToolCallRecord`** in `app/models.py` does **not** include `external_api_hint`; that field is **documentation-only** for SUB-2 / training. Production records include `called_at`, full `raw_result`, etc. **`tool_budget`** after burst = initial budget minus **number of burst tools executed** (see `burst_enrichment_node`).
"""
