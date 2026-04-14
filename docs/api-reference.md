# API Reference — SOC Triage Agent

**Base URL:** `http://localhost:8000`  
Replace `BASE` in the examples below with your deployment host (for example `https://soc-agent.example.com`).

This API is part of the **open source** SOC Triage Agent. See the [README](../README.md) for quick start and contributing; see [architecture.md](architecture.md) for pipeline design; see [AGENTS.md](../AGENTS.md) for how to extend tools and normalisers.

---

## Authentication

There is no separate “key issuance” API. The **`X-API-Key`** value is whatever you configure as **`API_KEY`** on the server. Clients send that **exact same string** on each protected request.

### Configuring API_KEY and X-API-Key

1. **Server:** From the repo root, copy the env template and edit it:
   ```bash
   cp .env.example .env
   ```
   In `.env`, set a strong secret, for example:
   ```bash
   API_KEY=your-long-random-secret-here
   ```
   Restart the app after changing `API_KEY` so the process picks up the new value.

2. **Client:** Use the **same** string as the header (no encoding step):
   ```http
   X-API-Key: your-long-random-secret-here
   ```
   Or equivalently:
   ```http
   Authorization: Bearer your-long-random-secret-here
   ```

3. **Shell scripts:** `export API_KEY='your-long-random-secret-here'` and pass **`-H "X-API-Key: $API_KEY"`** (double quotes around the header so the shell expands `$API_KEY`). If you use **single** quotes (`'X-API-Key: $API_KEY'`), curl sends the literal characters `$API_KEY`, not your secret — you will get **401**.

| Where | Value |
|-------|--------|
| **Header (preferred)** | `X-API-Key: <same value as API_KEY in server .env>` |
| **Header (alternate)** | `Authorization: Bearer <same value as API_KEY>` |

The server **does not** read the API key from the **query string** (e.g. `/ingest/auto?X-API-Key=...`). Put **`X-API-Key` and `Content-Type` only in headers**. Query parameters are ignored for authentication and may appear in access logs if used for secrets.

### Troubleshooting `401 Unauthorized`

| Mistake | Fix |
|---------|-----|
| Key only in URL (`?X-API-Key=...`) | Move the key to the **`X-API-Key` header**. |
| `Content-Type` in the URL | Use **`-H "Content-Type: application/json"`** only. |
| `'X-API-Key: $API_KEY'` (single quotes) | Use **`-H "X-API-Key: $API_KEY"`** (double quotes) or put the secret directly: `-H "X-API-Key: cyware@123"`. |
| Key does not match server | The header value must **exactly** equal `API_KEY` in the running server’s `.env` (restart after edits). |

**Working example** (secret contains `@`; use headers, no query string):

```bash
curl -sS -X POST "http://localhost:8000/ingest/auto" \
  -H "X-API-Key: cyware@123" \
  -H "Content-Type: application/json" \
  -d '{"event":{"DetectionId":"ldt:demo:001","DetectDescription":"Suspicious PowerShell","SeverityName":"High","ComputerName":"ws-01","FileName":"powershell.exe","CommandLine":"powershell -enc AAABBB","UserName":"jdoe"},"metadata":{"eventCreationTime":1744428600000}}'
```

Use your real `API_KEY` value in place of `cyware@123` if it differs.

Endpoints that call `validate_api_key` return **401** if the key is missing or wrong.

**Public (no API key):** `GET /health`, `GET /verdict/{alert_id}`.

**Protected (API key required):** all `POST` ingest routes, `GET /alert/{alert_id}`, `GET /jobs/{alert_id}`, `GET /stream/{alert_id}`, `POST /feedback`, `GET /metrics`.

---

## Conventions

| HTTP code | Meaning |
|-----------|---------|
| **200** | OK (sync read) |
| **201** | Created (feedback recorded) |
| **202** | Accepted (async triage queued) |
| **400** | Bad request (e.g. unknown `source`) |
| **401** | Unauthorized |
| **404** | Not found |
| **413** | Payload too large (> 1 MB on ingest bodies) |
| **422** | Unprocessable entity (normalisation / validation failed) |

**Shell helper** (optional):

```bash
export BASE="http://localhost:8000"
export API_KEY="change-me"   # must match server API_KEY
```

---

## 1. `POST /ingest/{source}`

**Description:** Ingest one raw alert from a known SIEM/EDR source. The pipeline normalises the payload, stores the alert, sets the job to `queued`, and runs triage **asynchronously**. Use `GET /verdict/{alert_id}` or `GET /jobs/{alert_id}` to follow progress.

**URL:** `POST {BASE}/ingest/{source}`

| Parameter | In | Required | Description |
|-----------|-----|----------|-------------|
| `source` | path | yes | One of: `splunk`, `crowdstrike`, `aws_guardduty`, `sentinel`, `generic` (case-insensitive). |
| `X-API-Key` or `Authorization: Bearer` | header | yes | Server API key. |
| *(body)* | JSON body | yes | Raw vendor alert JSON (shape depends on `source`). |

**cURL:**

```bash
curl -sS -X POST "$BASE/ingest/splunk" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "search_name": "DNS Tunneling Detection",
    "result": {
      "_time": "2026-04-12T04:15:00Z",
      "urgency": "high",
      "host": "workstation-045",
      "src_ip": "10.10.5.45",
      "dest_ip": "185.220.101.45",
      "message": "High-entropy DNS TXT queries detected.",
      "mitre_technique": "T1071.004"
    }
  }'
```

**Sample response (202):**

```json
{
  "alert_id": "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcd",
  "status": "queued",
  "message": "Alert accepted. Triage running asynchronously."
}
```

---

## 2. `POST /ingest/auto`

**Description:** Same as `/ingest/{source}` but the server **auto-detects** `AlertSource` from the JSON shape (Splunk `search_name`/`result`, CrowdStrike `event.DetectionId`, GuardDuty `detail-type`, Sentinel `properties.incidentNumber`, OCSF `class_uid` 2004, etc.). Common SOAR/webhook **wrappers** are peeled first (`data`, `alert`, `body`, `payload`, `properties`, `resource`, single-key `event`/`result`, and `records[0]`).

If the payload is still **generic** (no recognised vendor fingerprint), behaviour depends on **`AUTO_INGEST_COERCE_LLM`** (default `true` in `.env.example`): when enabled and Ollama or OpenAI is configured, the **fast model** maps the JSON into a flat `title` / `description` / `severity` / optional hostname and MITRE hints (structured output; no invented IOCs). When disabled or all LLM calls fail, the existing **generic** normaliser still runs on the expanded JSON (description may be a truncated JSON string).

The **entire** vendor alert is the HTTP body: one JSON object, `Content-Type: application/json`. See [Authentication](#authentication) for how **`X-API-Key`** matches **`API_KEY`** in the server `.env`.

Use the path **`/ingest/auto`** exactly (literal segment `auto`). It is **not** a value for `{source}` in `/ingest/{source}` — those are only `splunk`, `crowdstrike`, `aws_guardduty`, `sentinel`, and `generic`.

**URL:** `POST {BASE}/ingest/auto`

| Parameter | In | Required | Description |
|-----------|-----|----------|-------------|
| `X-API-Key` / Bearer | header | yes | Must equal the server’s `API_KEY` (see [Configuring API_KEY and X-API-Key](#configuring-api_key-and-x-api-key)). |
| *(body)* | JSON body | yes | **Whole** raw alert as a single JSON object (any shape the normaliser recognises). |

**cURL — inline JSON body (whole payload in the request):**

Paste or generate your alert JSON between the quotes after `-d`. This is equivalent to sending the same object from Postman’s **Body → raw → JSON**.

```bash
curl -sS -X POST "$BASE/ingest/auto" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
  "event": {
    "DetectionId": "ldt:demo:001",
    "DetectDescription": "Suspicious PowerShell",
    "SeverityName": "High",
    "ComputerName": "ws-01",
    "FileName": "powershell.exe",
    "CommandLine": "powershell -enc AAABBB",
    "UserName": "CORP\\jdoe"
  },
  "metadata": { "eventCreationTime": 1744428600000 }
}'
```

**cURL — Splunk-shaped whole body:**

```bash
curl -sS -X POST "$BASE/ingest/auto" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "search_name": "DNS Tunneling Detection",
    "result": {
      "_time": "2026-04-12T04:15:00Z",
      "urgency": "high",
      "host": "workstation-045",
      "src_ip": "10.10.5.45",
      "dest_ip": "185.220.101.45",
      "message": "High-entropy DNS TXT queries detected.",
      "mitre_technique": "T1071.004"
    }
  }'
```

**Optional — body from a file:** If the JSON is large or generated by another tool, you can still pass a file as the **entire** body (the file must contain **only** valid JSON, one value):

```bash
curl -sS -X POST "$BASE/ingest/auto" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @path/to/alert.json
```

(`--data-binary` avoids curl altering newlines; `-d @file` is also common.)

**Sample response (202)** — when CrowdStrike is detected from the body:

```json
{
  "alert_id": "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
  "detected_source": "crowdstrike",
  "status": "queued"
}
```

**Sample response (202)** — when Splunk is detected from the body:

```json
{
  "alert_id": "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcd",
  "detected_source": "splunk",
  "status": "queued"
}
```

---

## 3. `POST /ingest/batch`

**Description:** Queue **many** alerts in one request (golden replays, SOAR bulk). Each item is validated independently; failures do not stop other rows. Max **500** items per request.

**URL:** `POST {BASE}/ingest/batch`

| Parameter | In | Required | Description |
|-----------|-----|----------|-------------|
| `X-API-Key` / Bearer | header | yes | Server API key. |
| `items` | JSON body | yes | Array of `{ "source": "<AlertSource>", "payload": { ... } }`. |
| `items[].source` | body | per item | Same values as path `source` in `/ingest/{source}`. |
| `items[].payload` | body | per item | Raw alert object for that source. |

**cURL:**

```bash
curl -sS -X POST "$BASE/ingest/batch" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "items": [
      {
        "source": "splunk",
        "payload": {
          "search_name": "Test",
          "result": { "_time": "2026-04-12T04:00:00Z", "urgency": "medium", "message": "x" }
        }
      },
      {
        "source": "generic",
        "payload": { "class_uid": 2004, "finding_info": { "title": "Finding", "severity_id": 3 } }
      }
    ]
  }'
```

**Sample response (202):**

```json
{
  "accepted": 2,
  "total": 2,
  "results": [
    {
      "ok": true,
      "alert_id": "c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef12",
      "source": "splunk"
    },
    {
      "ok": true,
      "alert_id": "d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef1234",
      "source": "generic"
    }
  ]
}
```

**Sample row error (still 202 overall):**

```json
{
  "ok": false,
  "error": "Unknown source 'acme_siem'"
}
```

---

## 4. `GET /verdict/{alert_id}`

**Description:** Poll for the triage outcome. **No API key.** Returns `processing` while the job runs, `complete` with scrubbed verdict when done, `failed` with `error` if the background pipeline raised, or **404** if nothing exists for that id.

**URL:** `GET {BASE}/verdict/{alert_id}`

| Parameter | In | Required | Description |
|-----------|-----|----------|-------------|
| `alert_id` | path | yes | Value returned from `POST /ingest/*`. |

**cURL (processing):**

```bash
curl -sS "$BASE/verdict/b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"
```

**Sample response — processing (200):**

```json
{
  "alert_id": "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
  "status": "processing"
}
```

**Sample response — complete (200):**  
(`verdict` is passed through `scrub_verdict_for_log`; shape matches `TriageVerdict`.)

```json
{
  "alert_id": "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
  "status": "complete",
  "verdict": {
    "verdict_id": "9f1b2c3d-4e5f-6789-a012-b3c4d5e6f789",
    "alert_id": "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
    "generated_at": "2026-04-12T04:22:15.123456+00:00",
    "severity": "HIGH",
    "severity_justification": "DNS tunneling indicators align with T1071.004.",
    "mitre_assessments": [
      {
        "technique_id": "T1071.004",
        "technique_name": "DNS",
        "tactic": "Command and Control",
        "confidence": 0.92
      }
    ],
    "triage_summary": "Short narrative for the analyst.",
    "confirmed_iocs": [
      { "type": "ip", "value": "185.220.101.45", "context": "C2-related DNS" }
    ],
    "immediate_actions": [
      { "priority": 1, "action": "Block IP at perimeter", "target": "firewall" }
    ],
    "escalation": "ESCALATE_IR",
    "escalation_rationale": "…",
    "total_tool_calls": 5,
    "tools_called": ["query_netflow", "lookup_threat_intel"],
    "analyst_confidence": 0.88,
    "false_positive_probability": 0.07
  }
}
```

**Sample response — failed (200):**

```json
{
  "alert_id": "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
  "status": "failed",
  "error": "Connection refused to Ollama"
}
```

**404:** Unknown `alert_id` (no alert and no job context).

---

## 5. `GET /alert/{alert_id}`

**Description:** Returns the **normalised** `NormalizedAlert` (including `raw_payload` and optional `detection_finding` slice) for forensics or UI. Requires API key.

**URL:** `GET {BASE}/alert/{alert_id}`

| Parameter | In | Required | Description |
|-----------|-----|----------|-------------|
| `alert_id` | path | yes | Ingest response `alert_id`. |
| `X-API-Key` / Bearer | header | yes | Server API key. |

**cURL:**

```bash
curl -sS "$BASE/alert/b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef" \
  -H "X-API-Key: $API_KEY"
```

**Sample response (200):**  
Full serialised alert (abbreviated):

```json
{
  "alert_id": "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
  "source": "splunk",
  "source_alert_id": null,
  "title": "DNS Tunneling Detection",
  "description": "…",
  "severity": "HIGH",
  "timestamp": "2026-04-12T04:15:00+00:00",
  "hostname": "workstation-045",
  "network": { "src_ip": "10.10.5.45", "dst_ip": "185.220.101.45" },
  "mitre_technique": "T1071.004",
  "raw_payload": { "search_name": "…", "result": { } },
  "detection_finding": null
}
```

**404:** Alert not in store (expired process memory, wrong id, or Redis miss if used).

---

## 6. `GET /jobs/{alert_id}`

**Description:** Lightweight **job status** for automation: `queued`, `running`, `complete`, or `failed` plus optional `error` string. If an alert/verdict exists but no job record was written, status may be `unknown`. Requires API key.

**URL:** `GET {BASE}/jobs/{alert_id}`

| Parameter | In | Required | Description |
|-----------|-----|----------|-------------|
| `alert_id` | path | yes | Ingest response `alert_id`. |
| `X-API-Key` / Bearer | header | yes | Server API key. |

**cURL:**

```bash
curl -sS "$BASE/jobs/b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef" \
  -H "X-API-Key: $API_KEY"
```

**Sample responses (200):**

```json
{ "alert_id": "…", "status": "queued", "error": null }
```

```json
{ "alert_id": "…", "status": "running", "error": null }
```

```json
{ "alert_id": "…", "status": "complete", "error": null }
```

```json
{
  "alert_id": "…",
  "status": "failed",
  "error": "ValueError: …"
}
```

```json
{ "alert_id": "…", "status": "unknown" }
```

**404:** No alert, verdict, or job for that id.

---

## 7. `GET /stream/{alert_id}`

**Description:** **Server-Sent Events (SSE)** over ordinary **HTTP/HTTPS** — not WebSocket, not gRPC. The server keeps one **GET** response open and writes `data: …\n\n` lines (`Content-Type: text/event-stream`). Flow is **one-way** (server → client); you cannot send frames back on the same connection.

The first event is always **`{"phase":"open","alert_id":"…"}`** so the connection shows activity immediately. Status lines follow about **four per second** (`queued`, `running`, …) while triage runs. **If triage already finished** before you open the stream (verdict already in the store), you will only see **`open`** then **`complete`** in quick succession — that is expected. To watch live phases, start **`curl -N …/stream/…`** in one terminal, then **`POST /ingest/…`** from another, or use an `alert_id` that is still **running**.

**Postman and other GUIs** often **buffer** the whole SSE response until the HTTP connection closes, so it can look like “nothing live” even though the server is streaming — use **`curl -N`** in a terminal for real-time lines.

**Postman:** Use a normal **HTTP** request — **not** “WebSocket”, **not** “Socket.IO”, **not** “Streaming” modes that send `Connection: Upgrade` or open `…/socket.io/?EIO=4&transport=websocket`.

1. Click **New → HTTP** (or use the default request tab that shows method **GET** and **Params / Authorization / Headers / Body**).
2. Method **GET**. URL **only**: `http://localhost:8000/stream/9f3cf770306280ae` (no `curl`, no `socket.io` path).
3. **Headers:** `X-API-Key` = your server `API_KEY`; optional `Accept` = `text/event-stream`.

If Postman’s handshake shows **`/socket.io/`**, **`Upgrade: websocket`**, or status **403**, you are in the wrong request type — this API does not implement Socket.IO or WebSockets. Switch to plain **GET** as above, or use **terminal `curl -N`** (below).

Do **not** paste a full `curl ...` line into the URL field (*Could not connect to curl -sSN …*).

Postman may still buffer SSE until the response ends; for live lines, prefer **`curl -N`** or a small script.

**URL:** `GET {BASE}/stream/{alert_id}`

| Parameter | In | Required | Description |
|-----------|-----|----------|-------------|
| `alert_id` | path | yes | Ingest response `alert_id`. |
| `X-API-Key` / Bearer | header | yes | Server API key. |

**cURL** (use **`-N`** so SSE lines print as they arrive; replace `ALERT_ID` with the `alert_id` from `POST /ingest/auto` or `/ingest/{source}`):

```bash
curl -sSN "${BASE}/stream/ALERT_ID" \
  -H "X-API-Key: $API_KEY" \
  -H "Accept: text/event-stream"
```

Example after a CrowdStrike auto-ingest returns `{"alert_id":"9f3cf770306280ae",...}`:

```bash
curl -sSN "${BASE}/stream/9f3cf770306280ae" \
  -H "X-API-Key: $API_KEY" \
  -H "Accept: text/event-stream"
```

**Sample SSE lines (each event is one `data:` line + blank line):**

```
data: {"phase": "open", "alert_id": "9f3cf770306280ae"}

data: {"phase": "queued", "alert_id": "9f3cf770306280ae"}

data: {"phase": "running", "alert_id": "9f3cf770306280ae"}

data: {"phase": "complete", "verdict": { "...": "scrubbed TriageVerdict fields" }}
```

```
data: {"phase": "failed", "error": "…"}
```

```
data: {"phase": "timeout"}
```

---

## 8. `POST /feedback`

**Description:** Records **analyst feedback** for evaluation (`observability/feedback.py`). Agreement is inferred by comparing `original_verdict` to `analyst_decision` (or load original from stored verdict when `original_verdict` is omitted).

**URL:** `POST {BASE}/feedback`

| Parameter | In | Required | Description |
|-----------|-----|----------|-------------|
| `X-API-Key` / Bearer | header | yes | Server API key. |
| `alert_id` | JSON body | yes | Alert the feedback refers to. |
| `analyst_decision` | JSON body | yes | One of: `ESCALATE_IR`, `FALSE_POSITIVE`, `MONITOR`, `CLOSE`. |
| `original_verdict` | JSON body | no | Same enum; if omitted, loaded from stored verdict for `alert_id`. |
| `comment` | JSON body | no | Free text (default `""`). |
| `analyst_id` | JSON body | no | Identifier (default `"anonymous"`). |

**cURL:**

```bash
curl -sS -X POST "$BASE/feedback" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
    "analyst_decision": "FALSE_POSITIVE",
    "comment": "Rule too noisy on TXT lookups",
    "analyst_id": "jsmith"
  }'
```

**Sample response (201):**

```json
{ "status": "recorded" }
```

**404:** No stored verdict for `alert_id` when `original_verdict` is omitted.

---

## 9. `GET /health`

**Description:** Liveness probe for orchestrators and load balancers. **No API key.**

**URL:** `GET {BASE}/health`

| Parameter | In | Required | Description |
|-----------|-----|----------|-------------|
| *(none)* | — | — | — |

**cURL:**

```bash
curl -sS "$BASE/health"
```

**Sample response (200):**

```json
{
  "status": "ok",
  "service": "soc-triage-agent"
}
```

---

## 10. `GET /metrics`

**Description:** In-process pipeline counters plus **approximate** alert/verdict store sizes. With Redis persistence enabled, counts may be `-1` (unknown) and `persistence_backend` is `redis`. Requires API key.

**URL:** `GET {BASE}/metrics`

| Parameter | In | Required | Description |
|-----------|-----|----------|-------------|
| `X-API-Key` / Bearer | header | yes | Server API key. |

**cURL:**

```bash
curl -sS "$BASE/metrics" -H "X-API-Key: $API_KEY"
```

**Sample response (200) — in-memory backend:**

```json
{
  "pipeline": {
    "alerts_received": 47,
    "verdicts_generated": 45,
    "errors": 2,
    "avg_latency_ms": 18420.5
  },
  "verdict_store_size": 45,
  "alert_store_size": 47,
  "persistence_backend": "memory"
}
```

**Sample response (200) — Redis backend:**

```json
{
  "pipeline": { "alerts_received": 120, "verdicts_generated": 118, "errors": 1, "avg_latency_ms": 15200.0 },
  "verdict_store_size": -1,
  "alert_store_size": -1,
  "persistence_backend": "redis"
}
```

---

## Escalation decision values

Used in verdicts and in `POST /feedback` (`analyst_decision`, `original_verdict`).

| Value | Meaning |
|-------|---------|
| `ESCALATE_IR` | Confirmed threat — trigger incident response. |
| `FALSE_POSITIVE` | Not a real threat — close and tune. |
| `MONITOR` | Suspicious — watchlist. |
| `CLOSE` | Low signal — no action. |

---

## Splunk alert action integration

POST Splunk alert payloads to **`{BASE}/ingest/splunk`** with `X-API-Key`. Supports Alert Action shape (`result` wrapper) and HEC-style JSON.

**Minimal Python sender:**

```python
import json
import requests

def send_to_soc_agent(payload: dict, base_url: str, api_key: str) -> dict:
    r = requests.post(
        f"{base_url.rstrip('/')}/ingest/splunk",
        json=payload,
        headers={"X-API-Key": api_key},
        timeout=60,
    )
    r.raise_for_status()
    return r.json()
```

---

## CrowdStrike event stream integration

POST Falcon detection payloads to **`{BASE}/ingest/crowdstrike`** with `X-API-Key`. Expected shape includes top-level `event` and `metadata` (see sample data under `data/raw/` in the repo).
