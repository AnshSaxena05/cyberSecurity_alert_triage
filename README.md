# SOC Triage Agent

**Agentic SOC alert triage** service: ingest alerts from Splunk, CrowdStrike, AWS GuardDuty (and more), normalise them, enrich via MITRE-routed tools, and produce a structured **`TriageVerdict`** using LangGraph and LLM reasoning.

**Stack:** FastAPI · LangGraph · Pydantic · optional Ollama / OpenAI · optional Redis cache · optional Langfuse.

---

## Open source project

This is an **open source** codebase: behaviour, APIs, and architecture are documented in **`docs/`** and in [AGENTS.md](AGENTS.md) at the repo root so operators, contributors, and tooling (including AI agents) can rely on the same contracts.

| Document | What it covers |
|----------|----------------|
| [docs/architecture.md](docs/architecture.md) | End-to-end architecture — layers, LangGraph flow, security boundaries, degradation |
| [docs/api-reference.md](docs/api-reference.md) | HTTP API — ingest, verdicts, jobs, auth headers, async patterns |
| [AGENTS.md](AGENTS.md) | Extension patterns (new tools, sources, MITRE routes), testing expectations, env overview |

If you extend the service, prefer updating **`docs/`** alongside code so the open docs stay the single source of truth for reviewers and downstream users.

---

## Requirements

- **Python 3.14+** (see `pyproject.toml`)
- **[uv](https://docs.astral.sh/uv/)** recommended for installs and runs
- **Redis** (optional) — set `CACHE_ENABLED=false` in `.env` if you skip it
- **Ollama** or **OpenAI** (optional) — entity extraction and verdict generation can use local models or cloud fallback; see `.env.example`

---

## Install

From the repository root:

```bash
# Install uv (one-time): https://docs.astral.sh/uv/getting-started/installation/
uv venv --python 3.14 .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
uv pip install -e ".[dev]"
```

---

## Configure

```bash
cp .env.example .env
```

Edit `.env`. **Minimum to start the HTTP server and accept webhooks:**

| Variable   | Purpose                                      |
|-----------|-----------------------------------------------|
| `API_KEY` | Shared secret; send as header `X-API-Key` on ingest and protected reads |

Other variables (Splunk, CrowdStrike, OpenAI, Langfuse, Redis, etc.) are optional and documented in `.env.example`.

---

## Start the application

```bash
# From repo root, with venv activated
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Or with **uv** without activating the venv:

```bash
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Sanity check (no API key):**

```bash
curl -s http://localhost:8000/health
# {"status":"ok","service":"soc-triage-agent"}
```

**Interactive API (“debug” UI):** after the server is running, open:

| URL | Purpose |
|-----|---------|
| **http://localhost:8000/docs** | Swagger UI — browse operations, request/response schemas, **Try it out** |
| **http://localhost:8000/redoc** | ReDoc — same API, alternate layout |
| **http://localhost:8000/openapi.json** | Raw OpenAPI schema (import into Postman, Insomnia, etc.) |

`GET /health` can be executed from Swagger without authentication. **Ingest endpoints require the `X-API-Key` header** (see below); if your Swagger UI build does not let you attach that header easily, use **curl** or any REST client.

---

## Pass inputs (ingest alerts)

Triage runs **asynchronously**: `POST` returns `202` with an `alert_id`, then you poll **`GET /verdict/{alert_id}`** until `status` is `complete`.

### Authentication

Send the same value as `API_KEY` in `.env`:

```http
X-API-Key: <your-api-key>
```

(`Authorization: Bearer <same-value>` is also accepted by the server.)

### Option 1 — Swagger UI (`/docs`)

1. Go to **http://localhost:8000/docs**
2. Open **`POST /ingest/{source}`** or **`POST /ingest/auto`**
3. Click **Try it out**
4. Set **`source`** (for the path-style endpoint) to one of: `splunk`, `crowdstrike`, `aws_guardduty`, `sentinel`, `generic`
5. Paste a JSON **Request body** (examples below)
6. Add header **`X-API-Key`** with your key (use your client’s header support if the Swagger “Try it out” panel does not expose it)
7. **Execute** — copy `alert_id` from the response

Then call **`GET /verdict/{alert_id}`** (no API key required for verdict in the default app) until `status` is `complete`.

### Option 2 — curl

**Splunk-shaped alert:**

```bash
export API_KEY='your-key-from-env'
export BASE='http://localhost:8000'

RESP=$(curl -sS -X POST "$BASE/ingest/splunk" \
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
      "message": "847 high-entropy DNS TXT queries detected. 44MB exfil via DNS.",
      "mitre_technique": "T1071.004"
    }
  }')

echo "$RESP"
ALERT_ID=$(echo "$RESP" | python -c "import sys,json; print(json.load(sys.stdin)['alert_id'])")

curl -sS "$BASE/verdict/$ALERT_ID"
```

**Auto-detect source from payload:**

```bash
curl -sS -X POST "$BASE/ingest/auto" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d @data/raw/your_alert.json
```

### Debug: normalised alert and metrics

| Endpoint | Header | Description |
|----------|--------|-------------|
| `GET /alert/{alert_id}` | `X-API-Key` | Normalised **OCSF** alert JSON (after ingest) |
| `GET /metrics` | `X-API-Key` | Pipeline counters and in-memory store sizes |

---

## Optional: Ollama models

If you use local LLMs:

```bash
ollama pull llama3.2:3b
ollama pull axonvertex/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:Q8_0_24K
```

Set `OLLAMA_BASE_URL` in `.env` (e.g. `http://localhost:11434`). For cloud-only operation, configure `OPENAI_API_KEY` instead.

---

## Optional: Redis

```bash
docker run -d -p 6379:6379 redis:7-alpine
```

Or disable the cache:

```bash
# in .env
CACHE_ENABLED=false
```

---

## Local demo script (full pipeline, no HTTP)

Runs the same LangGraph pipeline as the API against a sample or file-based SIEM JSON:

```bash
uv run scripts/demo_siem_triage.py
# uv run scripts/demo_siem_triage.py --json-file path/to/alert.json --quiet
```

---

## Docker Compose

Full stack (app + Redis + Ollama) — see `docker-compose.yml`:

```bash
docker-compose up -d
```

---

## Tests

```bash
uv run pytest tests/ -v
```

No external APIs required for the default test suite.

---

## Project layout (short)

```
app/            FastAPI app, settings, Pydantic models
components/     Alert normalisation, entity extraction
services/       LangGraph triage pipeline, MITRE router, cache, query builders
agents/         Enrichment burst + tool implementations
prompts/        System prompts and registry
security/       API key, payload limits, filters
tests/          Pytest suite
```

---

## Contributing

Issues and pull requests are welcome. Before opening a PR:

1. Read [AGENTS.md](AGENTS.md) and the relevant sections of [docs/architecture.md](docs/architecture.md) if you touch the pipeline, tools, or models.
2. Run **`uv run pytest tests/ -v`** and keep the suite green.
3. Update **`docs/api-reference.md`** when you add or change HTTP surfaces so the open API docs stay accurate.

---

## License

Add a **`LICENSE`** file at the repository root and state the SPDX identifier here (for example MIT, Apache-2.0, or AGPL-3.0) so downstream users know how they may use and redistribute this open source project.
