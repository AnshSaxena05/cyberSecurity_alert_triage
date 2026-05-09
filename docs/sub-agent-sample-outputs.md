# Sample outputs: SUB-1 vs SUB-2

These are **illustrative** handoffs only. The live triage graph (`services/triage_pipeline.py`) uses Python nodes and Pydantic models; SUB-1/SUB-2 prompts are for **multi-agent wrappers**, **docs**, or **supervisor** LLMs.

---

## SUB-1 — Preprocessing (`PREPROCESSING_SUB_AGENT_SYSTEM_PROMPT`)

**Role:** OCSF-style normalisation, `ExtractedEntities`-style extraction, MITRE routing alignment, and **prediction** of burst tool order / param intent (see `mitre_router.py`, `enrichment_node.py`). Does **not** execute vendor APIs.

**Sample structured handoff (JSON):**

```json
{
  "agent": "SUB-1",
  "normalised": {
    "severity": "HIGH",
    "source": "splunk",
    "title": "Suspicious curl outbound to pastebin-like host",
    "description": "curl process initiated connection to external paste-style URL from web tier host.",
    "timestamp": "2026-04-14T12:00:00Z",
    "mitre_technique": "T1105",
    "mitre_tactic": "Command and Control",
    "network": {
      "src_ip": "10.0.1.50",
      "dst_ip": "203.0.113.50"
    }
  },
  "extracted_entities": {
    "hosts": [{ "hostname": "web-prod-07", "ip_addresses": ["10.0.1.50"] }],
    "users": [{ "username": "www-data" }],
    "processes": [{ "name": "curl", "cmdline": "curl -s https://paste.example/raw/abc123" }],
    "techniques": [
      {
        "technique_id": "T1105",
        "tactic": "Command and Control",
        "confidence": 0.9
      }
    ],
    "iocs": [
      { "type": "ip", "value": "203.0.113.50" },
      { "type": "domain", "value": "paste.example" }
    ],
    "attack_chain_summary": "Web workload invoked curl to an external host resembling a paste site, consistent with ingress tool or staged payload retrieval."
  },
  "technique_ids": ["T1105"],
  "primary_technique": "T1105",
  "get_time_window": { "hours": 72, "label": "72h" },
  "predicted_burst_tool_order": [
    "query_crowdstrike",
    "query_splunk",
    "lookup_threat_intel"
  ],
  "per_tool": [
    {
      "tool_name": "query_crowdstrike",
      "would_run": true,
      "reason": "Registry + param builder returns detections_by_host params",
      "expected_query_type": "detections_by_host",
      "expected_hostname": "web-prod-07"
    },
    {
      "tool_name": "query_splunk",
      "would_run": true,
      "reason": "Default process_by_host for non-matching T-prefix branches",
      "expected_query_type": "process_by_host",
      "expected_hostname": "web-prod-07"
    },
    {
      "tool_name": "lookup_threat_intel",
      "would_run": true,
      "reason": "IP IOC present on alert",
      "expected_ioc_type": "ip",
      "expected_ioc_value": "203.0.113.50"
    }
  ],
  "severity_budget_for_react": 8,
  "confidence": 0.82,
  "notes": "Merged order follows get_tools_for_techniques (priority_tool first per technique). Actual burst uses technique_ids[0] as primary_technique for _PARAM_BUILDERS."
}
```

---

## SUB-2 — Pipeline state & integration handoff (`PIPELINE_STATE_SUB_AGENT_SYSTEM_PROMPT`)

**Role:** Describe **LangGraph state** after `route_tools_node` and `burst_enrichment_node`: `tool_budget`, `phase`, `enrichment_data`, `tool_records`, external API hints. Does **not** normalise alerts or extract entities.

**Sample A — state patch after `route_tools` (conceptually what `route_tools_node` adds):**

```json
{
  "agent": "SUB-2",
  "stage": "after_route_tools_node",
  "state_update": {
    "tool_budget": 8,
    "phase": "burst"
  },
  "explanation": "HIGH severity maps to SEVERITY_BUDGET 8 in services/mitre_router.py. Next node is burst_enrichment."
}
```

**Sample B — state patch after `burst_enrichment` (matches shapes in `prompts/state_example_strings.py`; `external_api_hint` is doc-only, not on real `ToolCallRecord`):**

```json
{
  "agent": "SUB-2",
  "stage": "after_burst_enrichment_node",
  "state_update": {
    "enrichment_data": {
      "query_splunk": "[query_splunk] ERROR: [Errno 8] nodename nor servname provided, or not known",
      "lookup_threat_intel": "[ThreatIntel] IOC=203.0.113.50 Verdict=SUSPICIOUS — VT: 1/94 engines flagged | AbuseIPDB: 0% confidence, 12 reports | OTX: 1 threat pulses",
      "query_cmdb": "[query_cmdb] ERROR: ServiceNow CMDB request failed (HTTP error, timeout, or invalid credentials). Check instance URL, user ACLs on cmdb_ci, and logs."
    },
    "tools_called": ["query_splunk", "lookup_threat_intel", "query_cmdb"],
    "tool_budget": 5,
    "phase": "react"
  },
  "external_api_reference": [
    {
      "tool_name": "query_splunk",
      "external_api_hint": "Splunk REST — POST {base}/services/search/jobs (agents/tools/splunk_tool.py)"
    },
    {
      "tool_name": "lookup_threat_intel",
      "external_api_hint": "VirusTotal api/v3, AbuseIPDB api/v2/check, OTX api/v1 (agents/tools/threat_intel_tool.py)"
    },
    {
      "tool_name": "query_cmdb",
      "external_api_hint": "GET {instance}/api/now/table/cmdb_ci (agents/tools/cmdb_tool.py)"
    }
  ],
  "notes": "tool_budget = previous budget minus number of burst tasks executed. enrichment_data values are compressed strings from compress_tool_result in enrichment_node.py."
}
```

---

## SUB-3 — ReAct THINK (`SUB3_REACT_AGENT_THINK_SYSTEM_PROMPT`)

**Role:** Mimics `agent_think_node`: **`tocontinue`**, **`planned_tools`** (`name` + **`arguments`** as JSON string), **`reasoning`**. Inputs = alert + burst (and prior ReAct) enrichment. See `app/models.py` → `AgentThinkResponse`.

**Sample output (shape matches pipeline; arguments must match tool Pydantic schemas):**

```json
{
  "tocontinue": true,
  "planned_tools": [
    {
      "name": "query_crowdstrike",
      "arguments": "{\"query_type\":\"detections_by_host\",\"hostname\":\"web-prod-07\",\"hours_back\":72}"
    },
    {
      "name": "lookup_threat_intel",
      "arguments": "{\"ioc_type\":\"domain\",\"ioc_value\":\"paste.example\"}"
    }
  ],
  "reasoning": "Gaps remain on endpoint corroboration and domain reputation; planned tools address within budget."
}
```

Set **`tocontinue`: `false`** and **`planned_tools`: `[]`** when ready for verdict. If **`tool_budget`** is **0**, stop planning tools.

**Prompt helpers:** `get_sub3_react_agent_think_prompt()` · registry name `sub3_react_agent_think`.

---

## SUB-4 — Final verdict (`SUB4_VERDICT_GATE_SYSTEM_PROMPT`)

**Role:** Runs **only** when ReAct stops: **`tocontinue` is false**, or **`tool_budget` ≤ 0**, or no executable **`planned_tools`**. Outputs a single **`TriageVerdict`** JSON (`app/models.py`): `verdict_id`, `alert_id` (real pipeline id), `generated_at`, `severity`, `severity_justification`, `mitre_assessments`, `triage_summary`, `confirmed_iocs`, **exactly 3** `immediate_actions`, `escalation`, `escalation_rationale`, `total_tool_calls`, `tools_called`, `analyst_confidence`, `false_positive_probability`. Does **not** plan tools.

Some LLM APIs wrap the object in `role` / `content` / `additional_kwargs.parsed` — the **semantic** output is still **`TriageVerdict`**.

**Prompt helpers:** `get_sub4_verdict_gate_prompt()` · registry name `sub4_verdict_gate`.

---

## Quick comparison

| | SUB-1 | SUB-2 | SUB-3 | SUB-4 |
|---|--------|--------|--------|--------|
| **Typical output** | Normalised + entities + **predicted** burst plan | **route_tools** / **post-burst** state + API hints | **`tocontinue`** + **`planned_tools`** + **`reasoning`** | **`TriageVerdict`** only |
| **Primary code refs** | `alert_normalizer.py`, `entity_extractor.py`, `mitre_router.py`, `enrichment_node.py` | `triage_pipeline.py`, `state_example_strings.py` | `triage_pipeline.py` `agent_think_node`, `AgentThinkResponse` | `generate_verdict_node`, `TriageVerdict` |
