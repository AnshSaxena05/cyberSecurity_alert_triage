"""
Secret rotation publisher.

Standalone CLI that rotates HS256 service-token secrets on a fixed
cadence (24h by default). The actual rotation is one SQL statement in
``PostgresSecretStore.rotate``; this module schedules it, logs it, and
emits the NOTIFY that downstream workers listen for.

Usage:

    # one-shot rotation of all default audiences
    uv run python -m services._runtime.secret_publisher rotate

    # rotate one audience
    uv run python -m services._runtime.secret_publisher rotate --aud worker

    # run the scheduler (rotate every 24h, emit NOTIFY)
    uv run python -m services._runtime.secret_publisher run

The scheduler is best run as a small background service alongside the
API and workers. Multiple instances are safe — Postgres row-level lock
serialises the rotation, and only one instance's NOTIFY actually fires
per audience.
"""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

# Load .env from repo root before anything reads os.environ
_repo_root = Path(__file__).resolve().parent.parent.parent
_env_file = _repo_root / ".env"
if _env_file.exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(_env_file, override=False)
    except ImportError:
        pass

import structlog

from services._runtime.secret_store import (
    DEFAULT_AUDIENCES,
    PostgresSecretStore,
    secret_store_from_env,
)

logger = structlog.get_logger(__name__)

DEFAULT_INTERVAL_SECONDS = 24 * 60 * 60   # 24h


async def rotate_once(audiences: tuple[str, ...]) -> None:
    """One-shot rotation of the named audiences."""
    store = secret_store_from_env(seed_audiences=audiences)
    await store.initialize()
    try:
        for aud in audiences:
            bundle = await store.rotate(aud)
            logger.info(
                "secret_rotated",
                audience=aud,
                rotated_at=bundle.rotated_at,
            )
    finally:
        await store.close()


async def run_scheduler(
    audiences: tuple[str, ...],
    interval_seconds: int,
) -> None:
    """Long-running rotation loop. SIGINT exits cleanly."""
    store = secret_store_from_env(seed_audiences=audiences)
    await store.initialize()
    logger.info(
        "secret_publisher_started",
        audiences=list(audiences),
        interval_seconds=interval_seconds,
    )
    try:
        # On boot we don't rotate — first rotation happens after one full
        # interval, so a freshly-deployed system has time for workers to
        # come up and read the seeded secrets first.
        while True:
            try:
                await asyncio.sleep(interval_seconds)
            except asyncio.CancelledError:
                break
            for aud in audiences:
                try:
                    bundle = await store.rotate(aud)
                    logger.info(
                        "secret_rotated_scheduled",
                        audience=aud,
                        rotated_at=bundle.rotated_at,
                    )
                except Exception as exc:
                    logger.warning(
                        "secret_rotation_failed",
                        audience=aud,
                        error=str(exc),
                    )
    finally:
        await store.close()
        logger.info("secret_publisher_stopped")


def _parse_audiences(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return DEFAULT_AUDIENCES
    return tuple(a.strip() for a in raw.split(",") if a.strip())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_rotate = sub.add_parser("rotate", help="Rotate one or all audiences once and exit")
    p_rotate.add_argument(
        "--aud",
        default=None,
        help="Comma-separated audiences (default: worker,ingest,gateway)",
    )

    p_run = sub.add_parser("run", help="Long-running scheduler")
    p_run.add_argument(
        "--aud",
        default=None,
        help="Comma-separated audiences (default: worker,ingest,gateway)",
    )
    p_run.add_argument(
        "--interval-seconds",
        type=int,
        default=int(os.environ.get("SECRET_ROTATION_INTERVAL_SECONDS", DEFAULT_INTERVAL_SECONDS)),
    )

    args = parser.parse_args()
    auds = _parse_audiences(args.aud)

    if args.cmd == "rotate":
        asyncio.run(rotate_once(auds))
        return 0
    if args.cmd == "run":
        asyncio.run(run_scheduler(auds, args.interval_seconds))
        return 0
    parser.print_help()
    return 1


# Re-export so ``from services._runtime.secret_publisher import PostgresSecretStore``
# works without importing the secret_store module directly (a common pattern
# for ops scripts that want one entry point).
__all__ = [
    "rotate_once",
    "run_scheduler",
    "PostgresSecretStore",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
