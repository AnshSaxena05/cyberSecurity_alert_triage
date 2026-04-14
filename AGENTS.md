# AGENTS.md — SOC Triage Agent

This file is the primary context document for any AI agent working on this repository.
Read it completely before making any changes. It covers: project purpose, module ownership,
extension patterns, what must never be changed without review, and testing contracts.

---

## What This Project Does

This is a production-grade agentic SOC alert triage system. It receives raw security alerts
from SIEM and EDR platforms (Splunk, CrowdStrike, AWS GuardDuty), normalises them to OCSF schema,
extracts typed entities, routes to the correct enrichment tools via MITRE ATT&CK technique IDs,
fires those tools in parallel, and runs a LangGraph ReAct loop to produce a structured
`TriageVerdict` — all without human input.

The key distinction from a simple LLM chatbot: the majority of the pipeline is **deterministic**.
The LLM only reasons; it does not decide which source system to query first, how far back to
look, or what counts as a valid tool parameter. Those decisions are made by Python code.

---

## Repository Map

```
soc_analysis/
├── app/
│   ├── main.py              FastAPI entry point — alert ingestion webhooks, verdict retrieval
│   ├── config.py            Pydantic Settings — all env vars with defaults
│   ├── models.py            ALL Pydantic models — source of truth for data shapes
│   └── Dockerfile           Container image for the FastAPI app
│
├── components/
│   ├── alert_normalizer.py  Raw payload → OCSF NormalizedAlert (one parser per source)
│   └── entity_extractor.py  NormalizedAlert → ExtractedEntities via LLM or heuristic fallback
│
├── services/
│   ├── triage_pipeline.py   LangGraph StateGraph — the core engine, all nodes + edges
│   ├── mitre_router.py      TECHNIQUE_TO_TOOLS dict + time window table (deterministic)
│   ├── context_cache.py     Redis-backed IOC result cache (15-min TTL)
│   └── query_builder.py     SPL / KQL query string construction (no LLM, no string concat)
│
├── prompts/
│   ├── templates.py         System prompt strings by severity + technique class
│   └── registry.py          In-memory versioned prompt store (hot-swap without restart)
│
├── agents/
│   ├── enrichment_node.py   Burst enrichment: asyncio.gather over routing-table tools
│   └── tools/
│       ├── splunk_tool.py        SPL queries via Splunk REST API (real + SPLBuilder)
│       ├── crowdstrike_tool.py   CrowdStrike detections + process tree (OAuth2)
│       ├── threat_intel_tool.py  VirusTotal + AbuseIPDB + OTX in parallel
│       ├── aws_tool.py           CloudTrail + GuardDuty + IAM (boto3)
│       ├── cmdb_tool.py          ServiceNow CMDB when configured; else explicit error
│       ├── netflow_tool.py       NDR/flow connector placeholder (explicit error until wired)
│       └── backup_tool.py        Backup/VSS connector placeholder (explicit error until wired)
│
├── security/
│   ├── input_guard.py       API key auth + payload size check + injection scrubbing
│   ├── content_filter.py    Validate LLM tool call params before execution (SSRF, SPL injection)
│   └── output_filter.py     Scrub credentials/PII from verdict before logging
│
├── observability/
│   ├── tracer.py            OpenTelemetry spans; optional LangSmith
│   ├── langfuse_client.py   Langfuse (set LANGFUSE_BASE_URL to EU or US host)
│   ├── cost_tracker.py      Token usage + API call latency per alert
│   └── feedback.py          Analyst agreement/disagreement capture
│
├── evaluation/
│   ├── golden_alerts.json   6 labelled test alerts with expected severity + escalation
│   ├── online_monitor.py    Accuracy metrics: severity accuracy, escalation accuracy
│   └── eval_results/        Output directory for evaluation runs
│
├── data/
│   ├── raw/                 Sample raw alert payloads (Splunk, CrowdStrike, GuardDuty)
│   ├── processed/           Enriched verdict outputs for review
│   └── mitre_mappings/      technique_routing.yaml (human-readable routing reference)
│
├── tests/
│   ├── test_triage.py       End-to-end: normaliser, entities, routing, tools, security, burst
│   ├── test_entity_extraction.py   Heuristic extraction unit tests
│   └── test_routing.py      MITRE routing + time window + deduplication tests
│
├── docs/
│   ├── architecture.md      Deep technical architecture reference (read this second)
│   └── api-reference.md     FastAPI endpoint documentation
│
├── .env.example             Template for all required environment variables
├── docker-compose.yml       App + Redis + Ollama
├── pyproject.toml           Dependencies + pytest config
└── README.md                Quick-start guide
```

---

## The Six Architecture Layers

Understanding which layer owns which decision is critical before making any change.

| Layer | Name | Owner | Description |
|---|---|---|---|
| L1 | Entity Extraction | `components/entity_extractor.py` | LLM with structured output (llama3.2:3b). Falls back to regex heuristic. |
| L2 | MITRE → Tool Routing | `services/mitre_router.py` | Pure Python dict. Zero LLM. Maps T-code → ordered tool list + time window. |
| L3 | Tool Registry | `agents/tools/` | `@tool` decorated functions with Pydantic input schemas. LLM reads docstrings at runtime. |
| L4 | ReAct Loop | `services/triage_pipeline.py` | LangGraph cyclic graph: `agent_think` ↔ `execute_tool` conditional edge. |
| L5 | Budget Enforcement | `TriageState.tool_budget` | Integer in state, decremented per tool call. Edge checks `tool_budget <= 0`. |
| L6 | Time Windows | `services/mitre_router.py` | `TimeWindow` NamedTuples, set per technique class. Passed to tools, not chosen by LLM. |

---

## Data Flow (Sequential)

```
1. POST /ingest/{source}
       │
       ├── input_guard.py         API key check, size limit, injection scrub
       │
       ▼
2. alert_normalizer.py            Raw JSON → NormalizedAlert (OCSF schema)
   Source-specific parsers:       _parse_splunk / _parse_crowdstrike / _parse_guardduty
   Stable alert_id:               sha256(source + source_alert_id) — dedup safe
       │
       ▼
3. LangGraph: normalise_alert_node
   Sets severity string, phase = "extract"
       │
       ▼
4. LangGraph: extract_entities_node
   Calls extract_entities(alert, use_llm=True)
   → ChatOllama(fast_model) + with_structured_output(ExtractedEntities)
   → Falls back to _heuristic_extract() if Ollama unavailable
   Output: ExtractedEntities (hosts, users, processes, techniques, iocs)
       │
       ▼
5. LangGraph: route_tools_node
   Calls get_budget(severity) → sets tool_budget
   (tool list not selected here — happens in burst_enrichment_node)
       │
       ▼
6. LangGraph: burst_enrichment_node
   Calls get_tools_for_techniques(technique_ids) → ordered tool list
   For each tool: _PARAM_BUILDERS[tool](alert, entities, technique_id) → typed params
   asyncio.gather(*tasks) → all tools fire in parallel with asyncio.timeout()
   Each result → compress_tool_result() → ≤200 token string
   All compressed results → state["enrichment_data"]
   Budget decremented by number of tools fired
       │
       ▼
7. LangGraph: agent_think_node (Foundation-Sec-8B)
   SystemMessage: build_triage_prompt(severity, budget, tool_descriptions, enrichment_summary)
   HumanMessage: alert title + entities + all burst enrichment
   LLM: with_structured_output(AgentThinkResponse) — fields ``tocontinue`` (bool), ``planned_tools``, ``reasoning``
   Emits AIMessage with tool_calls[] derived from validated planned_tools (or empty when stopping)
   Conditional edge ``should_continue_react``: ``tocontinue`` AND ``tool_budget`` > 0 AND non-empty tool_calls → execute
       │
       ├── [all above true]
       │         │
       ▼         ▼
8. LangGraph: execute_tool_node
   Reads last_msg.tool_calls[0]
   Validates params via content_filter.validate_tool_params()
   Calls _execute_single_tool(tool_name, params) with cache check
   Result → ToolMessage → appended to state["messages"]
   tool_budget -= 1
       │
       └── loops back to agent_think_node
       │
       ▼ [budget = 0 OR ``tocontinue`` false OR no tool_calls on last AIMessage]
9. LangGraph: generate_verdict_node
   build_verdict_prompt(alert, entities, all enrichment)
   ChatOllama(deep_model) + with_structured_output(TriageVerdict)
   Falls back to _fallback_verdict() if LLM fails
       │
       ▼
10. POST /verdict/{alert_id}
    output_filter.scrub_verdict_for_log(verdict)
    Returned to caller
```

---

## Extension Patterns

### Adding a new alert source

1. Add enum value to `AlertSource` in `app/models.py`
2. Write `_parse_yourplatform(payload)` in `components/alert_normalizer.py`
3. Register it in `_PARSERS` dict at bottom of normalizer
4. Update `detect_source()` heuristic
5. Add a test in `tests/test_triage.py::TestAlertNormaliser`

### Adding a new MITRE technique

Edit `TECHNIQUE_TO_TOOLS` in `services/mitre_router.py`:

```python
"T1XXX.YYY": RoutingEntry(
    tools=["query_crowdstrike", "query_splunk"],
    time_window=PROCESS_EXECUTION_WINDOW,   # choose the correct constant
    priority_tool="query_crowdstrike",       # optional
),
```

Then add a test in `tests/test_routing.py`.

### Adding a new tool

1. Create `agents/tools/yourtool.py` following the pattern:
   - Define `YourToolInput(BaseModel)` with typed fields and Field descriptions
   - Write `async yourtool_async(params: YourToolInput) -> dict[str, Any]`
   - Decorate with `@tool("your_tool_name", args_schema=YourToolInput)` — docstring IS the LLM description
   - Return `{"source_available": False, "error": "..."}` on failure, never raise
2. Register in `agents/enrichment_node.py::_get_tool_registry()`
3. Add a param builder in `_PARAM_BUILDERS` dict
4. Add a compress handler in `compress_tool_result()`
5. List in `agent_think_node` `available_tools` list
6. Smoke test in `tests/test_triage.py::TestToolSmoke`

### Updating prompt templates

All system prompts are in `prompts/templates.py`. They are versioned via
`prompts/registry.py`. To hot-swap without restart:

```python
from prompts.registry import registry
registry.register("triage_system", "v1.1", NEW_PROMPT_STRING, set_active=True)
```

---

## What Must NOT Be Changed Without Review

These components have contracts that many other parts depend on. Changing them
requires updating all callers.

| Component | Contract |
|---|---|
| `app/models.py` | All Pydantic schemas. `TriageVerdict` field names map to the 6-section SOC analyst format. `NormalizedAlert` is the single normalisation contract. |
| `TriageState` in `triage_pipeline.py` | TypedDict keys. All nodes read/write from this. Adding a key is safe; removing or renaming breaks all nodes. |
| `TECHNIQUE_TO_TOOLS` key format | Always `"T{4digits}"` or `"T{4digits}.{3digits}"`. The `get_routing()` function does parent fallback by splitting on `.`. |
| Tool return format | Every tool must return `dict[str, Any]` with `source_available: bool`. The burst node and execute node both check this. |
| `compress_tool_result()` signature | Always `(tool_name: str, result: dict) -> str`. The pipeline inserts the string directly into LLM messages. |
| Golden alerts schema | `evaluation/golden_alerts.json` keys `expected_severity` and `expected_escalation` are used by `online_monitor.py` accuracy computation. |

---

## Environment Variables

All config is in `app/config.py` via `pydantic_settings.BaseSettings`. Full list in `.env.example`.

Minimum to run offline (no Ollama, no APIs):
```
CACHE_ENABLED=false
API_KEY=any-string
```

Minimum for full pipeline with local LLM:
```
OLLAMA_BASE_URL=http://localhost:11434
DEEP_MODEL=axonvertex/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:Q8_0_24K
FAST_MODEL=llama3.2:3b
CACHE_ENABLED=false   (or set REDIS_URL if Redis is running)
API_KEY=change-me
```

---

## Testing

Use **Python 3.14+** (see `pyproject.toml` `requires-python`). Create the venv with `uv venv --python 3.14 .venv`.

Tests are offline-safe by default (no Ollama, no Redis, no external APIs needed).

```bash
# Run all tests
uv run pytest tests/ -v

# Run a specific module
uv run pytest tests/test_routing.py -v

# Run async tests individually
uv run pytest tests/test_triage.py::TestEnrichmentBurst -v
```

Test coverage by file:

| Test file | What it covers |
|---|---|
| `test_triage.py` | Normaliser (all sources), entity extraction, MITRE routing, cache, security layers, all tool smoke tests, burst enrichment, SPL query builder |
| `test_entity_extraction.py` | Heuristic extraction: IP filtering, hash capture, technique ID extraction, process flagging, renamed-binary detection via cmdline |
| `test_routing.py` | All golden alert techniques have routing, deduplication, priority tool ordering, parent T-code fallback, time window exact values |

---

## Model Tiers

| Stage | Model | Why |
|---|---|---|
| Entity extraction (L1) | `llama3.2:3b` | Deterministic JSON output, <1s, structured_output mode |
| ReAct reasoning (L4) | `Foundation-Sec-8B` | Pre-trained on CVEs, MITRE ATT&CK, SOC triage data |
| Verdict generation | `Foundation-Sec-8B` | Domain knowledge required for technique → tactic mapping |

Both models run via Ollama at `OLLAMA_BASE_URL`. The `keep_alive: -1` setting keeps
models resident in RAM between requests, eliminating cold-start latency.

Context window: `OLLAMA_NUM_CTX=8192` (default). For CRITICAL alerts with many tool results,
increase to 16384 if hardware allows. The burst node compresses all tool results to ≤200 tokens
each so 8192 is sufficient for most cases.

---

## Security Boundaries

Three guard layers in `security/`:

1. **input_guard.py** — runs before normalisation. Rejects oversized payloads (>1MB),
   invalid API keys, and scrubs SQL/HTML injection patterns from all string fields.

2. **content_filter.py** — runs inside `execute_tool_node` before every LLM-requested
   tool call. Blocks dangerous SPL keywords (`delete`, `drop`), SSRF targets
   (`169.254.169.254`, `metadata.google.internal`), and excessively large time windows.
   This prevents prompt injection attacks where a malicious alert payload tricks the LLM
   into making dangerous tool calls.

3. **output_filter.py** — scrubs credential patterns (`password=...`, `token=...`) and
   credit card numbers from verdict strings before they are logged or returned.

---

## Graceful Degradation Chain

The pipeline never crashes on partial failures:

```
Ollama down            → entity_extractor falls back to _heuristic_extract()
Tool API timeout       → tool returns {"source_available": False, "error": "timeout"}
Redis down             → context_cache disables itself, pipeline continues without cache
LLM verdict fails      → _fallback_verdict() constructs minimal verdict from state
All tools fail         → burst_enrichment_node returns empty enrichment, LLM reasons from alert only
```

No node raises an unhandled exception — all errors are caught and logged via structlog.

---

## Glossary

| Term | Definition |
|---|---|
| OCSF | Open Cybersecurity Schema Framework — standardised event schema used to normalise alerts |
| ReAct | Reasoning + Acting — LLM pattern: THINK about what to do → ACT (call tool) → OBSERVE result |
| Burst enrichment | Firing all routing-table tools in parallel before LLM reasoning starts |
| Tool budget | Integer in TriageState limiting how many additional tool calls the LLM can make beyond the burst |
| Context compression | Reducing raw tool API responses to ≤200-token summaries before inserting into LLM context |
| Golden alerts | Labelled test cases with known-correct severity and escalation decisions |
| IOC | Indicator of Compromise — IP, hash, domain, URL with a reputation signal |
| T-code | MITRE ATT&CK technique identifier, e.g. T1003.001 |
| FDR | CrowdStrike Falcon Data Replicator — raw endpoint telemetry stream |
| SPL | Splunk Processing Language — Splunk's query language |
| KQL | Kusto Query Language — Microsoft Sentinel's query language |
