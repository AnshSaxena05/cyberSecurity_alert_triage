#!/usr/bin/env python3.14
"""
Read-only connectivity checks for integrations configured in repo-root `.env`.

Does not print secret values — only PASS / FAIL / SKIP and HTTP status or error type.

Usage (from repo root):

  uv run scripts/test_connector_creds.py

Exit code: 0 if every *configured* connector passes; 1 if any configured connector fails.
Skipped (empty creds) does not fail the run.
"""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.chdir(_REPO_ROOT)

try:
    from dotenv import load_dotenv

    load_dotenv(_REPO_ROOT / ".env", override=False)
except ImportError:
    pass

import httpx  # noqa: E402

from app.config import get_settings  # noqa: E402


def _mask(s: str, show: int = 4) -> str:
    if not s:
        return "(empty)"
    if len(s) <= show * 2:
        return "***"
    return f"{s[:show]}…{s[-show:]}"


def _line(name: str, status: str, detail: str) -> None:
    print(f"{name:22} {status:8} {detail}")


def _splunk_connection(s: Any) -> tuple[str, int, str]:
    """
    Return (host, port, scheme) for REST. Accepts SPLUNK_HOST as bare host or full URL
    (common misconfiguration: https://host:8089/ in SPLUNK_HOST).
    """
    raw = (s.splunk_host or "").strip()
    if not raw:
        return "", s.splunk_port, s.splunk_scheme
    if "://" in raw:
        u = urlparse(raw if "://" in raw else f"https://{raw}")
        host = u.hostname or ""
        port = u.port or s.splunk_port
        scheme = (u.scheme or s.splunk_scheme).lower()
        return host, port, scheme
    return raw, s.splunk_port, s.splunk_scheme


def test_splunk(s: Any, client: Any) -> tuple[str, str]:
    host, port, scheme = _splunk_connection(s)
    if not host:
        return "SKIP", "SPLUNK_HOST empty or unparsable"
    if not s.splunk_token and not (s.splunk_username and s.splunk_password):
        return "SKIP", "need SPLUNK_TOKEN or SPLUNK_USERNAME+SPLUNK_PASSWORD"

    base = f"{scheme}://{host}:{port}"
    headers: dict[str, str] = {}
    auth: Any = None
    if s.splunk_token:
        headers["Authorization"] = f"Bearer {s.splunk_token}"
    else:
        auth = (s.splunk_username, s.splunk_password)

    try:
        r = client.get(
            f"{base}/services/server/info",
            params={"output_mode": "json"},
            headers=headers,
            auth=auth,
        )
    except httpx.ConnectTimeout:
        return (
            "FAIL",
            "connect timed out — host/port likely unreachable (VPN, firewall, wrong SPLUNK_HOST, "
            "or Splunk not listening). Larger TOOL_TIMEOUT_SECONDS usually does not fix this.",
        )
    except httpx.ReadTimeout:
        return (
            "FAIL",
            "read timed out — TLS/connect ok but Splunk did not finish the HTTP response in time.",
        )
    except httpx.ConnectError as exc:
        return "FAIL", f"connect failed: {str(exc)[:140]} — check scheme/host/port and SPLUNK_VERIFY_SSL"
    except httpx.TimeoutException as exc:
        return "FAIL", f"timed out ({exc!s})"

    if r.status_code == 200:
        return "PASS", f"HTTP {r.status_code} server={host}:{port}"
    return "FAIL", f"HTTP {r.status_code} {_mask(r.text[:120])}"


def test_crowdstrike(s: Any, client: Any) -> tuple[str, str]:
    if not s.crowdstrike_client_id or not s.crowdstrike_client_secret:
        return "SKIP", "CROWDSTRIKE_CLIENT_ID/SECRET empty"
    r = client.post(
        f"{s.crowdstrike_base_url.rstrip('/')}/oauth2/token",
        data={
            "client_id": s.crowdstrike_client_id,
            "client_secret": s.crowdstrike_client_secret,
        },
    )
    if r.status_code == 201 and "access_token" in r.text:
        return "PASS", f"HTTP {r.status_code} oauth2 token ok"
    if r.status_code == 200 and "access_token" in r.text:
        return "PASS", f"HTTP {r.status_code} oauth2 token ok"
    hint = ""
    try:
        body = r.json()
        errs = body.get("errors", [])
        if errs:
            hint = f" — {errs[0].get('message', '')[:120]}"
    except Exception:
        pass
    if r.status_code == 400 and not hint:
        hint = (
            " — OAuth rejected: wrong CROWDSTRIKE_CLIENT_SECRET, wrong CROWDSTRIKE_BASE_URL for your "
            "cloud (e.g. api.us-2.crowdstrike.com, api.eu-1.crowdstrike.com), or revoked API client. "
            "Timeouts do not fix HTTP 400."
        )
    return "FAIL", f"HTTP {r.status_code}{hint}" if hint else f"HTTP {r.status_code} {_mask(r.text[:120])}"


def test_virustotal(s: Any, client: Any) -> tuple[str, str]:
    if not s.virustotal_api_key:
        return "SKIP", "VIRUSTOTAL_API_KEY empty"
    r = client.get(
        "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
        headers={"x-apikey": s.virustotal_api_key},
    )
    if r.status_code in (200, 404):
        return "PASS", f"HTTP {r.status_code} (key accepted)"
    if r.status_code == 401:
        return "FAIL", "HTTP 401 invalid API key"
    return "FAIL", f"HTTP {r.status_code} {_mask(r.text[:120])}"


def test_abuseipdb(s: Any, client: Any) -> tuple[str, str]:
    if not s.abuseipdb_api_key:
        return "SKIP", "ABUSEIPDB_API_KEY empty"
    r = client.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": "1.1.1.1", "maxAgeInDays": 90},
        headers={"Key": s.abuseipdb_api_key, "Accept": "application/json"},
    )
    if r.status_code == 200:
        return "PASS", "HTTP 200 check ok"
    if r.status_code == 401:
        return "FAIL", "HTTP 401 invalid key"
    return "FAIL", f"HTTP {r.status_code} {_mask(r.text[:120])}"


def test_otx(s: Any, client: Any) -> tuple[str, str]:
    if not s.otx_api_key:
        return "SKIP", "OTX_API_KEY empty"
    r = client.get(
        "https://otx.alienvault.com/api/v1/user/me",
        headers={"X-OTX-API-KEY": s.otx_api_key},
    )
    if r.status_code == 200:
        return "PASS", "HTTP 200 user/me ok"
    if r.status_code == 401:
        return "FAIL", "HTTP 401 invalid key"
    return "FAIL", f"HTTP {r.status_code} {_mask(r.text[:120])}"


def test_servicenow(s: Any, client: Any) -> tuple[str, str]:
    if not s.servicenow_instance_url:
        return "SKIP", "SERVICENOW_INSTANCE_URL empty"
    if not s.servicenow_username:
        return "SKIP", "SERVICENOW_USERNAME empty"

    base = s.servicenow_instance_url.rstrip("/")
    if s.servicenow_client_id and s.servicenow_client_secret:
        tr = client.post(
            f"{base}/oauth_token.do",
            data={
                "grant_type": "password",
                "client_id": s.servicenow_client_id,
                "client_secret": s.servicenow_client_secret,
                "username": s.servicenow_username,
                "password": s.servicenow_password,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if tr.status_code != 200 or "access_token" not in tr.text:
            return "FAIL", f"oauth HTTP {tr.status_code} {_mask(tr.text[:100])}"
        token = tr.json().get("access_token", "")
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    else:
        raw = f"{s.servicenow_username}:{s.servicenow_password}".encode()
        headers = {
            "Authorization": f"Basic {base64.b64encode(raw).decode()}",
            "Accept": "application/json",
        }

    r = client.get(
        f"{base}/api/now/table/cmdb_ci",
        params={"sysparm_limit": 1},
        headers=headers,
    )
    if r.status_code == 200:
        return "PASS", "HTTP 200 cmdb_ci table ok"
    if r.status_code == 401:
        return "FAIL", "HTTP 401 auth failed"
    return "FAIL", f"HTTP {r.status_code} {_mask(r.text[:120])}"


def test_vulncheck(s: Any, client: Any) -> tuple[str, str]:
    if not s.vulncheck_api_token:
        return "SKIP", "VULNCHECK_API_TOKEN empty"
    r = client.get(
        "https://api.vulncheck.com/v3/index",
        headers={
            "Authorization": f"Bearer {s.vulncheck_api_token}",
            "Content-Type": "application/json",
        },
    )
    if r.status_code == 200:
        return "PASS", "HTTP 200 index ok"
    if r.status_code == 401:
        return "FAIL", "HTTP 401 invalid token"
    return "FAIL", f"HTTP {r.status_code} {_mask(r.text[:120])}"


def test_aws(s: Any) -> tuple[str, str]:
    if not s.aws_access_key_id or not s.aws_secret_access_key:
        return "SKIP", "AWS keys empty"
    try:
        import boto3  # type: ignore[import]
    except ImportError:
        return "SKIP", "boto3 not installed (uv pip install -e .)"

    try:
        sts = boto3.client(
            "sts",
            aws_access_key_id=s.aws_access_key_id,
            aws_secret_access_key=s.aws_secret_access_key,
            region_name=s.aws_region,
        )
        ident = sts.get_caller_identity()
        aid = ident.get("Account", "?")
        arn = ident.get("Arn", "")
        return "PASS", f"account={aid} {_mask(arn, 20)}"
    except Exception as e:
        return "FAIL", str(e)[:160]


def test_redis(s: Any) -> tuple[str, str]:
    if not s.cache_enabled:
        return "SKIP", "CACHE_ENABLED=false"
    try:
        import redis  # type: ignore[import]
    except ImportError:
        return "SKIP", "redis package missing"

    try:
        r = redis.from_url(s.redis_url, socket_connect_timeout=5)
        if r.ping():
            return "PASS", "PING ok"
        return "FAIL", "PING returned false"
    except Exception as e:
        es = str(e).lower()
        if "refused" in es or "10061" in es or "error 61" in es or "timed out" in es:
            return "SKIP", "Redis not reachable (optional — start Redis or set CACHE_ENABLED=false)"
        return "FAIL", str(e)[:160]


def test_openai(s: Any, client: Any) -> tuple[str, str]:
    if not s.openai_api_key:
        return "SKIP", "OPENAI_API_KEY empty"
    r = client.get(
        "https://api.openai.com/v1/models",
        params={"limit": 1},
        headers={"Authorization": f"Bearer {s.openai_api_key}"},
    )
    if r.status_code == 200:
        return "PASS", f"HTTP 200 model={s.openai_model!r}"
    if r.status_code == 401:
        return "FAIL", "HTTP 401 invalid key"
    return "FAIL", f"HTTP {r.status_code} {_mask(r.text[:120])}"


def test_ollama(s: Any, client: Any) -> tuple[str, str]:
    base = s.ollama_base_url.rstrip("/")
    try:
        r = client.get(f"{base}/api/tags", timeout=5.0)
    except Exception as e:
        es = str(e).lower()
        if "refused" in es or "connection refused" in es or "61" in es:
            return "SKIP", "Ollama not running (optional local LLM)"
        return "FAIL", f"connect error: {e!s}"[:160]
    if r.status_code == 200:
        return "PASS", f"HTTP 200 {base}"
    return "FAIL", f"HTTP {r.status_code}"


def test_langfuse(s: Any, client: Any) -> tuple[str, str]:
    if not s.langfuse_enabled:
        return "SKIP", "LANGFUSE_ENABLED=false"
    if not s.langfuse_public_key or not s.langfuse_secret_key:
        return "SKIP", "Langfuse keys empty"
    base = s.langfuse_base_url.rstrip("/")
    r = client.get(f"{base}/api/public/health")
    if r.status_code == 200:
        return "PASS", f"HTTP 200 health {_mask(base, 24)}"
    return "WARN", f"public health HTTP {r.status_code} (keys not verified)"


def main() -> int:
    get_settings.cache_clear()
    s = get_settings()

    print("Connector credential checks (values from .env are never printed)")
    sh, sp, ssch = _splunk_connection(s)
    print(f"Splunk target (masked): {ssch}://{_mask(sh or '', 12)}:{sp}")
    http_timeout = float(s.tool_timeout_seconds)
    print(f"HTTP timeouts (Splunk + other connectors): {http_timeout:.0f}s (TOOL_TIMEOUT_SECONDS / tool_timeout_seconds)")
    print("-" * 72)

    fail = 0
    # Splunk uses its own client for SPLUNK_VERIFY_SSL; both clients share the same wait budget.
    splunk_wait = httpx.Timeout(http_timeout)
    with httpx.Client(timeout=http_timeout, verify=True) as client:
        splunk_verify = s.splunk_verify_ssl
        with httpx.Client(timeout=splunk_wait, verify=splunk_verify) as splunk_client:
            for name, fn in (
                ("Splunk", lambda: test_splunk(s, splunk_client)),
                ("CrowdStrike", lambda: test_crowdstrike(s, client)),
                ("VirusTotal", lambda: test_virustotal(s, client)),
                ("AbuseIPDB", lambda: test_abuseipdb(s, client)),
                ("OTX (AlienVault)", lambda: test_otx(s, client)),
                ("ServiceNow CMDB", lambda: test_servicenow(s, client)),
                ("VulnCheck", lambda: test_vulncheck(s, client)),
            ):
                try:
                    status, detail = fn()
                except Exception as e:
                    status, detail = "FAIL", str(e)[:200]
                _line(name, status, detail)
                if status == "FAIL":
                    fail += 1

        for name, fn in (
            ("AWS STS", lambda: test_aws(s)),
            ("Redis cache", lambda: test_redis(s)),
            ("OpenAI API", lambda: test_openai(s, client)),
            ("Ollama", lambda: test_ollama(s, client)),
            ("Langfuse health", lambda: test_langfuse(s, client)),
        ):
            try:
                status, detail = fn()
            except Exception as e:
                status, detail = "FAIL", str(e)[:200]
            _line(name, status, detail)
            if status == "FAIL":
                fail += 1

    print("-" * 72)
    if fail:
        print(f"Result: {fail} configured connector(s) FAILED (see above).")
        return 1
    print("Result: no failures among configured connectors (SKIP/WARN do not fail).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
