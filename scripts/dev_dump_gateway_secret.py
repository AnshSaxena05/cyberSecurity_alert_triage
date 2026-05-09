#!/usr/bin/env python3
"""
Dump the gateway audience's HS256 secret to ``gateway/.dev.vars``.

The Cloudflare Worker / Durable Object cannot read Postgres directly, so
the gateway service-token secret has to land on the Worker side via
``wrangler secret put`` (production) or a ``.dev.vars`` file (local).

Run after ``services._runtime.secret_publisher rotate`` (or after
FastAPI's first boot, which seeds the same row). Re-run after every
secret rotation.

    uv run python scripts/dev_dump_gateway_secret.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# Load .env from repo root so SECRETS_PG_URL / POSTGRES_URL are available
_repo_root = Path(__file__).resolve().parent.parent
_env_file = _repo_root / ".env"
if _env_file.exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(_env_file, override=False)
    except ImportError:
        pass

REPO_ROOT = Path(__file__).resolve().parent.parent
DEV_VARS_PATH = REPO_ROOT / "gateway" / ".dev.vars"


async def main() -> int:
    dsn = (
        os.environ.get("SECRETS_PG_URL")
        or os.environ.get("POSTGRES_URL")
        or "postgresql://soc:soc@localhost:5432/soc_checkpoint"
    )
    try:
        import asyncpg
    except ImportError:
        print("asyncpg is not installed; run `uv sync --all-extras` first.", file=sys.stderr)
        return 1

    try:
        conn = await asyncpg.connect(dsn=dsn, timeout=5)
    except Exception as exc:
        print(f"could not connect to Postgres at {dsn}: {exc}", file=sys.stderr)
        return 1

    try:
        row = await conn.fetchrow(
            "SELECT current_secret FROM service_secrets WHERE audience = $1",
            "gateway",
        )
    finally:
        await conn.close()

    if not row:
        print(
            "no service_secrets row for audience='gateway'.\n"
            "run `uv run python -m services._runtime.secret_publisher rotate` first.",
            file=sys.stderr,
        )
        return 1

    secret = row["current_secret"]
    DEV_VARS_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEV_VARS_PATH.write_text(f'GATEWAY_SERVICE_TOKEN_SECRET="{secret}"\n')
    print(f"wrote {DEV_VARS_PATH.relative_to(REPO_ROOT)} ({len(secret)} chars)")
    print("for production, use:  cd gateway && wrangler secret put GATEWAY_SERVICE_TOKEN_SECRET")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
