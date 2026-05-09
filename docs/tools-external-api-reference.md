# External APIs used by `agents/tools/`

This document lists **vendor and integration HTTP/API surfaces** referenced in each tool module: **base URL**, **auth**, and **paths** (where applicable). It is derived from the current implementation and `app/config.py` settings.

For the SOC Triage Agent **FastAPI** routes, see [`api-reference.md`](api-reference.md).

---

## `splunk_tool.py` (`query_splunk`)

| Item | Value |
|------|--------|
| **Base URL** | `{SPLUNK_SCHEME}://{SPLUNK_HOST}:{SPLUNK_PORT}` (defaults: `https://localhost:8089`) |
| **Auth** | **Either** HTTP Basic: `SPLUNK_USERNAME` + `SPLUNK_PASSWORD` **or** `Authorization: Bearer {SPLUNK_TOKEN}` when `SPLUNK_TOKEN` is set (token preferred). |
| **TLS** | `SPLUNK_VERIFY_SSL` controls certificate verification. |

**Endpoints (relative to base)**

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/services/search/jobs` | Create search job (`search`, `output_mode`, `count`) |
| `GET` | `/services/search/jobs/{sid}` | Poll job status until `dispatchState == DONE` |
| `GET` | `/services/search/jobs/{sid}/results` | Fetch results (`output_mode`, `count`) |

---

## `crowdstrike_tool.py` (`query_crowdstrike`)

| Item | Value |
|------|--------|
| **Base URL** | `CROWDSTRIKE_BASE_URL` (default `https://api.crowdstrike.com`). Use the Falcon API hostname for your cloud (e.g. US-1, US-2, EU-1). |
| **Auth** | **OAuth2 client credentials:** `POST …/oauth2/token` with `client_id` + `client_secret` (`CROWDSTRIKE_CLIENT_ID`, `CROWDSTRIKE_CLIENT_SECRET`). Access token is cached and sent as `Authorization: Bearer …` on API calls. |

**Endpoints** (paths are relative to `CROWDSTRIKE_BASE_URL`; client uses `httpx` with `base_url` set)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/oauth2/token` | Obtain bearer token |
| `GET` | `/detects/queries/detects/v1` | List detection IDs (FQL filter) |
| `POST` | `/detects/entities/summaries/GET/v1` | Detection summaries by IDs |
| `GET` | `/processes/entities/processes/v1` | Process entities (process tree) |
| `GET` | `/devices/queries/devices/v1` | Device ID query |
| `GET` | `/devices/entities/devices/v2` | Device details |
| `GET` | `/iocs/queries/indicators/v1` | IOC indicator query |
| `GET` | `/alerts/queries/alerts/v2` | Alert IDs |
| `POST` | `/alerts/entities/alerts/v2` | Alert details |
| `GET` | `/incidents/queries/incidents/v1` | Incident IDs |
| `POST` | `/incidents/entities/incidents/GET/v1` | Incident details |

---

## `threat_intel_tool.py` (`lookup_threat_intel`)

Three fixed public bases; each uses its own API key from settings.

### VirusTotal

| Item | Value |
|------|--------|
| **Base URL** | `https://www.virustotal.com/api/v3` |
| **Auth** | Header `x-apikey: {VIRUSTOTAL_API_KEY}` |

**Paths** (appended to base; IOC-type dependent)

| Method | Path pattern | Notes |
|--------|--------------|--------|
| `GET` | `/ip_addresses/{ip}` | IP lookups |
| `GET` | `/domains/{domain}` | Domain lookups |
| `GET` | `/files/{hash}` | SHA256/MD5 file hashes |
| `GET` | `/urls/{base64url}` | URL (Base64url-encoded) |

### AbuseIPDB

| Item | Value |
|------|--------|
| **Base URL** | `https://api.abuseipdb.com/api/v2` |
| **Auth** | Header `Key: {ABUSEIPDB_API_KEY}` (and `Accept: application/json`) |

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/check` | Query params: `ipAddress`, `maxAgeInDays`, `verbose` (IP IOCs only in this tool) |

### AlienVault OTX

| Item | Value |
|------|--------|
| **Base URL** | `https://otx.alienvault.com/api/v1` |
| **Auth** | Header `X-OTX-API-KEY: {OTX_API_KEY}` |

| Method | Path pattern | Purpose |
|--------|--------------|---------|
| `GET` | `/indicators/{type}/{ioc_value}/general` | `type` is `IPv4`, `domain`, `file`, or `URL` (see `threat_intel_tool.py`) |

---

## `aws_tool.py` (`query_aws`)

| Item | Value |
|------|--------|
| **Base URL** | **Not fixed in code.** Uses **AWS SDK (`boto3`)**; requests go to **regional AWS service endpoints** for the configured region (e.g. `cloudtrail`, `guardduty`, `iam` clients in `AWS_REGION`, default `us-east-1`). |
| **Auth** | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (session credentials); standard AWS credential chain applies if extended later. |

**API usage (high level)**

- **CloudTrail:** `lookup_events` (paginated) for user- and event-based lookups.
- **GuardDuty:** `list_detectors`, `list_findings`, `get_findings`.

---

## `cmdb_tool.py` (`query_cmdb`) — ServiceNow

| Item | Value |
|------|--------|
| **Instance base** | `SERVICENOW_INSTANCE_URL` (e.g. `https://yourinstance.service-now.com`) — no path suffix in the setting. |
| **Auth** | **Option A — OAuth2 (password grant):** `POST {instance}/oauth_token.do` with `grant_type=password`, `client_id`, `client_secret`, `username`, `password` → `Authorization: Bearer` on Table API calls. **Option B — Basic:** `Authorization: Basic base64(SERVICENOW_USERNAME:SERVICENOW_PASSWORD)` when OAuth client credentials are not set. |

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/oauth_token.do` | OAuth token (when `SERVICENOW_CLIENT_ID` + `SERVICENOW_CLIENT_SECRET` are set) |
| `GET` | `/api/now/table/cmdb_ci` | CMDB CI query (`sysparm_query`, `sysparm_limit`, `sysparm_display_value`) |

---

## `vulncheck_tool.py` (`lookup_vulncheck`)

| Item | Value |
|------|--------|
| **Base URL** | `https://api.vulncheck.com/v3` (constant `VULNCHECK_BASE` in code) |
| **Auth** | `Authorization: Bearer {VULNCHECK_API_TOKEN}` |

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/index/vulncheck-nvd2` | Query param: `cve` (CVE ID) |

---

## `netflow_tool.py` (`query_netflow` / `query_dns_logs`)

| Item | Value |
|------|--------|
| **Base URL** | **`NDR_FLOW_API_URL`** — full URL for a **single POST** endpoint (your NDR/flow/DNS integration). Not a vendor constant in-repo. |
| **Auth** | Optional `Authorization: Bearer {NDR_FLOW_API_TOKEN}` when `NDR_FLOW_API_TOKEN` is set. |

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | *Value of `NDR_FLOW_API_URL`* | JSON body: `query_type`, `src_ip`, `dst_ip`, `hostname`, `hours_back`, `threshold_bytes` |

---

## `backup_tool.py` (`query_backup_systems`)

| Item | Value |
|------|--------|
| **Base URL** | **`BACKUP_API_URL`** — full URL for a **single POST** endpoint (your backup vendor bridge). Not a vendor constant in-repo. |
| **Auth** | Optional `Authorization: Bearer {BACKUP_API_TOKEN}` when `BACKUP_API_TOKEN` is set. |

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | *Value of `BACKUP_API_URL`* | JSON body: `query_type`, `hostname`, `hours_back` |

---

## Environment variable quick map

| Setting | Used by |
|---------|---------|
| `SPLUNK_SCHEME`, `SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_USERNAME`, `SPLUNK_PASSWORD`, `SPLUNK_TOKEN`, `SPLUNK_VERIFY_SSL` | Splunk |
| `CROWDSTRIKE_BASE_URL`, `CROWDSTRIKE_CLIENT_ID`, `CROWDSTRIKE_CLIENT_SECRET` | CrowdStrike |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` | AWS |
| `SERVICENOW_INSTANCE_URL`, `SERVICENOW_USERNAME`, `SERVICENOW_PASSWORD`, `SERVICENOW_CLIENT_ID`, `SERVICENOW_CLIENT_SECRET` | ServiceNow |
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY` | Threat intel |
| `VULNCHECK_API_TOKEN` | VulnCheck |
| `NDR_FLOW_API_URL`, `NDR_FLOW_API_TOKEN` | NetFlow/NDR |
| `BACKUP_API_URL`, `BACKUP_API_TOKEN` | Backup |

See also `.env.example` for descriptions and defaults.

---

*Generated to match `agents/tools/*.py` and `app/config.py`. Update this file when adding or changing integrations.*
