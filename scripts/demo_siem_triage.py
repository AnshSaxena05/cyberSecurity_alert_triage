#!/usr/bin/env python3.14
"""
Demo: ingest a SIEM (Sysmon-style) JSON alert, run the full triage pipeline with
real enrichment tools (Splunk, CrowdStrike, threat intel, etc. per MITRE routing).

Each tool call is echoed to stderr (params + raw response) and optionally mirrored
to Langfuse as an event when LANGFUSE_ENABLED=true.

LLM steps use the pipeline fallback chain: local Ollama → OpenAI.
Set credentials in repo-root `.env` for connectors you want live (see `.env.example`).

Usage (from repo root; Python 3.14+):

  uv run scripts/demo_siem_triage.py

  uv run scripts/demo_siem_triage.py --with-ollama
  uv run scripts/demo_siem_triage.py --json-file path/to/sysmon.json
  uv run scripts/demo_siem_triage.py --disable-langfuse
  uv run scripts/demo_siem_triage.py --quiet

Requires repo root on PYTHONPATH (run from repo root as above).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Bootstrap: repo root + .env before any project imports (settings cache)
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _load_dotenv() -> None:
    """Load repo-root `.env` so OLLAMA_*, API_KEY, etc. match the FastAPI app."""
    try:
        from dotenv import load_dotenv

        path = _REPO_ROOT / ".env"
        load_dotenv(path, override=False)
    except ImportError:
        pass


def _apply_langfuse_from_dotenv_file() -> None:
    """
    Re-apply Langfuse-related keys from `.env` so they win over the shell.
    """
    path = _REPO_ROOT / ".env"
    if not path.is_file():
        return
    try:
        from dotenv import dotenv_values
    except ImportError:
        return
    vals = dotenv_values(path)
    for key in (
        "LANGFUSE_ENABLED",
        "LANGFUSE_SECRET_KEY",
        "LANGFUSE_PUBLIC_KEY",
        "LANGFUSE_BASE_URL",
        "LANGFUSE_PROMPT_MANAGEMENT",
    ):
        raw = vals.get(key)
        if raw is None or str(raw).strip() == "":
            continue
        os.environ[key] = str(raw).strip().strip('"').strip("'")


def _maybe_enable_langfuse_from_env_keys() -> None:
    """
    If `.env` defines Langfuse keys but omits LANGFUSE_ENABLED, turn tracing on.
    Respects explicit LANGFUSE_ENABLED=false. Ignores placeholder keys from .env.example.
    """
    sk = os.environ.get("LANGFUSE_SECRET_KEY", "").strip().strip('"')
    pk = os.environ.get("LANGFUSE_PUBLIC_KEY", "").strip().strip('"')
    if not sk or not pk:
        return
    if "..." in sk or "..." in pk:
        return
    raw = os.environ.get("LANGFUSE_ENABLED")
    if raw is not None and str(raw).strip().lower() in ("false", "0", "no"):
        return
    if raw is None or str(raw).strip() == "":
        os.environ["LANGFUSE_ENABLED"] = "true"


# Raw SIEM / Sysmon-style event (embedded default sample)
SYSMON_SIEM_ALERT: dict[str, Any] = {
    "EventTime": "2026-04-12T10:15:22.451Z",
    "EventID": 1,
    "ProviderName": "Microsoft-Windows-Sysmon",
    "Computer": "WIN-FIN-DESK-04.corp.local",
    "UserData": {
        "RuleName": "Detect_Office_Spawning_PowerShell",
        "UtcTime": "2026-04-12 10:15:22.451",
        "ProcessGuid": "{A1B2C3D4-E5F6-7890-1234-567890ABCDEF}",
        "ProcessId": "8192",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "FileVersion": "10.0.19041.1",
        "Description": "Windows PowerShell",
        "Product": "Microsoft® Windows® Operating System",
        "Company": "Microsoft Corporation",
        "OriginalFileName": "PowerShell.EXE",
        "CommandLine": (
            "powershell.exe -nop -w hidden -ep bypass -EncodedCommand SQBuAHYAbwBrAG..."
        ),
        "CurrentDirectory": "C:\\Users\\jsmith\\Documents\\",
        "User": "CORP\\jsmith",
        "LogonGuid": "{A1B2C3D4-0000-0000-0000-000000000000}",
        "LogonId": "0x3f5c9",
        "TerminalSessionId": "1",
        "IntegrityLevel": "Medium",
        "Hashes": (
            "SHA256=908B64B1971A979C7E3E8CE4621945CBA84854CB98D76367B791A6E22B5F6D53"
        ),
        "ParentProcessGuid": "{A1B2C3D4-1111-2222-3333-444455556666}",
        "ParentProcessId": "4028",
        "ParentImage": (
            "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
        ),
        "ParentCommandLine": (
            '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" '
            '/n "C:\\Users\\jsmith\\Downloads\\Q2_Invoice_04122026.docm"'
        ),
    },
}


def _flatten_sysmon_to_splunk_result(raw: dict[str, Any]) -> dict[str, Any]:
    """Map nested Sysmon-style JSON into fields the Splunk normaliser understands."""
    ud = raw.get("UserData") or {}
    img = ud.get("Image") or ""
    proc_name = img.split("\\")[-1] or "powershell.exe"
    parent_img = ud.get("ParentImage") or ""
    parent_name = parent_img.split("\\")[-1] if parent_img else None
    hashes = ud.get("Hashes") or ""
    sha256 = None
    if "SHA256=" in hashes.upper():
        for part in hashes.split(","):
            part = part.strip()
            if part.upper().startswith("SHA256="):
                sha256 = part.split("=", 1)[-1].strip()
                break

    return {
        "_time": raw.get("EventTime", raw.get("timestamp")),
        "sid": "demo-sysmon-office-powershell-20260412",
        "host": raw.get("Computer"),
        "urgency": "high",
        "severity": "high",
        "process_name": proc_name,
        "process_path": img,
        "command_line": ud.get("CommandLine"),
        "parent_process_name": parent_name,
        "process_id": ud.get("ProcessId"),
        "user": ud.get("User"),
        "sha256": sha256,
        "mitre_technique": "T1059.001",
        "message": (
            f"Sysmon EID {raw.get('EventID')}: {ud.get('RuleName')} — "
            f"{parent_name or 'Office'} spawned {proc_name} with suspicious flags."
        ),
    }


def build_splunk_webhook_payload(siem: dict[str, Any]) -> dict[str, Any]:
    """Shape like Splunk alert action: search_name + result row."""
    return {
        "search_name": siem.get("UserData", {}).get(
            "RuleName", "Detect_Office_Spawning_PowerShell"
        ),
        "result": _flatten_sysmon_to_splunk_result(siem),
    }


def _print_banner(title: str, *, quiet: bool) -> None:
    if quiet:
        return
    line = "=" * min(72, max(len(title) + 8, 16))
    print(f"\n{line}\n  {title}\n{line}\n", file=sys.stderr)


def _print_json(label: str, obj: Any, *, quiet: bool) -> None:
    if quiet:
        return
    print(f"\n>>> {label}", file=sys.stderr)
    print(json.dumps(obj, indent=2, default=str), file=sys.stderr)


def _log_tool_to_langfuse(tool_name: str, params: dict[str, Any], data: dict[str, Any]) -> None:
    try:
        from observability.langfuse_client import get_langfuse, is_enabled
    except Exception:
        return
    if not is_enabled():
        return
    lf = get_langfuse()
    if lf is None:
        return
    try:
        lf.create_event(
            name=f"demo_siem_triage:tool:{tool_name}",
            input=params,
            output=data,
            metadata={"script": "demo_siem_triage", "tool": tool_name},
        )
    except Exception as exc:
        print(f"[langfuse] create_event failed for {tool_name}: {exc}", file=sys.stderr)


def _install_tool_trace_hook(*, quiet: bool) -> None:
    """Wrap _execute_single_tool to log each call (stderr + Langfuse); always uses real APIs."""
    import agents.enrichment_node as en

    _orig = en._execute_single_tool

    async def _traced(
        tool_name: str,
        params: dict[str, Any],
        timeout_seconds: int = 15,
    ) -> Any:
        out = await _orig(tool_name, params, timeout_seconds)
        tname, data, _record = out
        _print_banner(f"TOOL: {tname}", quiet=quiet)
        _print_json("params", params, quiet=quiet)
        _print_json("response", data, quiet=quiet)
        _log_tool_to_langfuse(tname, params, data)
        return out

    en._execute_single_tool = _traced  # type: ignore[method-assign]


def _load_siem_json(args: argparse.Namespace) -> dict[str, Any]:
    if args.json_file:
        path = Path(args.json_file)
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    return SYSMON_SIEM_ALERT


async def _async_main(args: argparse.Namespace) -> int:
    _load_dotenv()
    if not args.disable_langfuse:
        _apply_langfuse_from_dotenv_file()
    if not args.with_ollama:
        os.environ["OLLAMA_BASE_URL"] = ""
    if args.disable_langfuse:
        os.environ["LANGFUSE_ENABLED"] = "false"
    else:
        _maybe_enable_langfuse_from_env_keys()

    from app.config import get_settings

    get_settings.cache_clear()
    from observability.langfuse_client import connect_langfuse, langfuse_flush

    settings = get_settings()
    connect_langfuse(
        secret_key=settings.langfuse_secret_key,
        public_key=settings.langfuse_public_key,
        host=settings.langfuse_base_url,
        enabled=settings.langfuse_enabled,
    )
    if settings.langfuse_enabled and not args.quiet:
        pk = settings.langfuse_public_key or ""
        pk_hint = f"{pk[:8]}…" if len(pk) > 8 else "(set)"
        print(
            f"\n>>> Langfuse: enabled (host={settings.langfuse_base_url}, public_key={pk_hint})\n",
            file=sys.stderr,
        )

    from components.alert_normalizer import normalize_alert
    from app.models import AlertSource
    from services.triage_pipeline import run_triage

    _install_tool_trace_hook(quiet=args.quiet)

    siem_raw = _load_siem_json(args)
    payload = build_splunk_webhook_payload(siem_raw)
    _print_banner("INPUT — Splunk-shaped webhook (flattened Sysmon)", quiet=args.quiet)
    _print_json("raw_siem", siem_raw, quiet=args.quiet)
    _print_json("splunk_payload", payload, quiet=args.quiet)

    alert = normalize_alert(AlertSource.SPLUNK, payload)
    _print_banner("NORMALISED ALERT", quiet=args.quiet)
    _print_json("NormalizedAlert", json.loads(alert.model_dump_json()), quiet=args.quiet)

    _print_banner("RUNNING TRIAGE PIPELINE (live tools)", quiet=args.quiet)
    t0 = time.perf_counter()
    try:
        verdict = await run_triage(alert)
    finally:
        if settings.langfuse_enabled:
            langfuse_flush()

    elapsed = time.perf_counter() - t0

    _print_banner("VERDICT", quiet=args.quiet)
    _print_json("TriageVerdict", json.loads(verdict.model_dump_json()), quiet=args.quiet)
    if not args.quiet:
        print(f"\n>>> pipeline_wall_time_s: {elapsed:.2f}", file=sys.stderr)
    else:
        print(json.dumps(json.loads(verdict.model_dump_json()), indent=2, default=str))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SIEM JSON → Splunk-shaped payload → full triage (real tool APIs)."
    )
    parser.add_argument(
        "--with-ollama",
        action="store_true",
        help="Use OLLAMA_BASE_URL from .env for LLM steps (default: clear Ollama, use OpenAI).",
    )
    parser.add_argument(
        "--disable-langfuse",
        action="store_true",
        help="Force LANGFUSE_ENABLED=false after loading .env.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress stderr banners/tool dumps; print only final verdict JSON to stdout.",
    )
    parser.add_argument(
        "--json-file",
        type=str,
        default="",
        help="Path to SIEM JSON file (Sysmon-style with UserData); default uses embedded sample.",
    )
    args = parser.parse_args()
    try:
        raise SystemExit(asyncio.run(_async_main(args)))
    except KeyboardInterrupt:
        raise SystemExit(130) from None


if __name__ == "__main__":
    main()
