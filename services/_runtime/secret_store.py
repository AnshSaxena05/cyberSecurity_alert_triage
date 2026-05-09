"""
HS256 service-token secret store.

Replaces Vault for v1. Secrets are stored in Postgres with a small,
purposeful schema:

    CREATE TABLE service_secrets (
        audience       TEXT  PRIMARY KEY,
        current_secret TEXT  NOT NULL,
        previous_secret TEXT,
        rotated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

Why a flat table (not a Vault-style KV with paths)?
  * One row per audience (worker / ingest / gateway) — fewer than ten
    rows ever exist.
  * Rotation is "shift current → previous, set new current, bump
    rotated_at" in a single SQL statement.
  * Easy to back up alongside the rest of the application data.

Why Postgres rather than Redis?
  * Stronger durability — secrets are operationally critical; an AOF
    second-window data loss on Redis is unacceptable for crypto material.
  * Transactional rotation — the "shift" must be atomic.

The user can switch to a Redis backend by implementing the same
``SecretStore`` Protocol in a separate module if their ops requirements
flip.

Concurrency:
  * One ``PostgresSecretStore`` per process; the asyncpg pool is shared.
  * ``rotate`` is transactional via row-level lock so two rotators do
    not interleave.
  * Read path uses LISTEN/NOTIFY so workers see new secrets within
    seconds of a rotation, not on a poll cycle.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import time
from typing import Protocol

import structlog

from services._runtime.jwt_service import SecretBundle

logger = structlog.get_logger(__name__)

DEFAULT_AUDIENCES = ("worker", "ingest", "gateway")
NEW_SECRET_BYTES = 32          # produces a 256-bit secret, urlsafe-encoded
ROTATION_NOTIFY_CHANNEL = "service_secret_rotated"


class SecretStore(Protocol):
    """Backend-agnostic interface."""

    async def initialize(self) -> None: ...

    async def get_bundle(self, audience: str) -> SecretBundle: ...

    async def rotate(self, audience: str) -> SecretBundle: ...

    async def close(self) -> None: ...


# ---------------------------------------------------------------------------
# In-memory implementation — used by unit tests and as a degraded-mode
# fallback when Postgres is unreachable on boot.
# ---------------------------------------------------------------------------


class InMemorySecretStore:
    """Synchronous in-process store. Suitable for tests and bootstrap-only dev."""

    def __init__(self, *, seed_audiences: tuple[str, ...] = DEFAULT_AUDIENCES) -> None:
        self._bundles: dict[str, SecretBundle] = {}
        for aud in seed_audiences:
            self._bundles[aud] = SecretBundle(
                audience=aud,
                current=_new_secret(),
                previous=None,
                rotated_at=time.time(),
            )

    async def initialize(self) -> None:
        return None

    async def get_bundle(self, audience: str) -> SecretBundle:
        bundle = self._bundles.get(audience)
        if bundle is None:
            raise KeyError(f"unknown audience {audience!r}")
        return bundle

    async def rotate(self, audience: str) -> SecretBundle:
        old = self._bundles.get(audience)
        new = _new_secret()
        prev = old.current if old is not None else None
        self._bundles[audience] = SecretBundle(
            audience=audience,
            current=new,
            previous=prev,
            rotated_at=time.time(),
        )
        return self._bundles[audience]

    async def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# Postgres implementation
# ---------------------------------------------------------------------------


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS service_secrets (
    audience        TEXT        PRIMARY KEY,
    current_secret  TEXT        NOT NULL,
    previous_secret TEXT,
    rotated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION notify_service_secret_rotated() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('service_secret_rotated', NEW.audience);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS service_secrets_rotated ON service_secrets;
CREATE TRIGGER service_secrets_rotated
AFTER INSERT OR UPDATE ON service_secrets
FOR EACH ROW EXECUTE FUNCTION notify_service_secret_rotated();
"""


class PostgresSecretStore:
    """
    Postgres-backed secret store with LISTEN/NOTIFY rotation watch.

    Construct with a Postgres URL (e.g. ``postgresql://soc:soc@localhost:5432/soc_checkpoint``);
    call ``initialize()`` once on boot to ensure the schema exists and an
    initial bundle exists for each audience.
    """

    def __init__(
        self,
        dsn: str,
        *,
        seed_audiences: tuple[str, ...] = DEFAULT_AUDIENCES,
        on_rotate=None,                  # async fn(audience) when LISTEN fires
    ) -> None:
        self._dsn = dsn
        self._seed = tuple(seed_audiences)
        self._on_rotate = on_rotate
        self._pool = None
        self._listener_conn = None
        self._listener_task: asyncio.Task | None = None

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------

    async def initialize(self) -> None:
        """Create the table + trigger; seed missing audiences."""
        import asyncpg

        self._pool = await asyncpg.create_pool(dsn=self._dsn, min_size=1, max_size=4)
        async with self._pool.acquire() as conn:
            await conn.execute(_SCHEMA_SQL)
            for aud in self._seed:
                # Insert if missing — never overwrite an existing secret on boot.
                await conn.execute(
                    """
                    INSERT INTO service_secrets (audience, current_secret)
                    VALUES ($1, $2)
                    ON CONFLICT (audience) DO NOTHING
                    """,
                    aud,
                    _new_secret(),
                )
        if self._on_rotate is not None:
            await self._start_listener()

    async def close(self) -> None:
        if self._listener_task is not None:
            self._listener_task.cancel()
        if self._listener_conn is not None:
            try:
                await self._listener_conn.close()
            except Exception:
                pass
        if self._pool is not None:
            await self._pool.close()

    # -----------------------------------------------------------------
    # Read / rotate
    # -----------------------------------------------------------------

    async def get_bundle(self, audience: str) -> SecretBundle:
        if self._pool is None:
            raise RuntimeError("PostgresSecretStore.initialize() must be called first")
        row = await self._pool.fetchrow(
            "SELECT audience, current_secret, previous_secret, "
            "EXTRACT(EPOCH FROM rotated_at) AS rotated_at_epoch "
            "FROM service_secrets WHERE audience = $1",
            audience,
        )
        if row is None:
            raise KeyError(f"unknown audience {audience!r}")
        return SecretBundle(
            audience=row["audience"],
            current=row["current_secret"],
            previous=row["previous_secret"],
            rotated_at=float(row["rotated_at_epoch"]),
        )

    async def rotate(self, audience: str) -> SecretBundle:
        """
        Atomically: shift current → previous, set new current, bump rotated_at.
        Trigger fires NOTIFY service_secret_rotated.
        """
        if self._pool is None:
            raise RuntimeError("PostgresSecretStore.initialize() must be called first")
        new = _new_secret()
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                # Lock the row so two rotators don't both stamp.
                row = await conn.fetchrow(
                    "SELECT current_secret FROM service_secrets WHERE audience = $1 FOR UPDATE",
                    audience,
                )
                if row is None:
                    # Allow rotate() to also create a missing audience entry.
                    await conn.execute(
                        "INSERT INTO service_secrets (audience, current_secret) VALUES ($1, $2)",
                        audience,
                        new,
                    )
                else:
                    await conn.execute(
                        "UPDATE service_secrets "
                        "SET previous_secret = current_secret, "
                        "    current_secret  = $1, "
                        "    rotated_at      = NOW() "
                        "WHERE audience = $2",
                        new,
                        audience,
                    )
        return await self.get_bundle(audience)

    # -----------------------------------------------------------------
    # LISTEN/NOTIFY watcher
    # -----------------------------------------------------------------

    async def _start_listener(self) -> None:
        import asyncpg

        self._listener_conn = await asyncpg.connect(dsn=self._dsn)
        await self._listener_conn.add_listener(
            ROTATION_NOTIFY_CHANNEL,
            self._on_notify,
        )
        # Keep the connection alive so notifications flow.
        self._listener_task = asyncio.create_task(self._heartbeat())

    async def _heartbeat(self) -> None:
        try:
            while True:
                await asyncio.sleep(60)
                if self._listener_conn is not None:
                    try:
                        await self._listener_conn.execute("SELECT 1")
                    except Exception as exc:
                        logger.warning("secret_store_heartbeat_failed", error=str(exc))
        except asyncio.CancelledError:
            pass

    def _on_notify(self, _conn, _pid, _channel, payload: str) -> None:
        # NOTIFY payload is the audience name; schedule the user-supplied
        # callback. Do not await here — asyncpg gives us a sync callback.
        if self._on_rotate is None:
            return
        try:
            asyncio.create_task(self._on_rotate(payload))
        except Exception as exc:
            logger.warning("secret_store_on_rotate_failed", payload=payload, error=str(exc))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _new_secret() -> str:
    """256-bit URL-safe secret, suitable for HS256 (>= 32 raw bytes)."""
    return secrets.token_urlsafe(NEW_SECRET_BYTES)


def secret_store_from_env(
    *,
    seed_audiences: tuple[str, ...] = DEFAULT_AUDIENCES,
    on_rotate=None,
) -> SecretStore:
    """
    Build a SecretStore from environment.

    Selection rule:
      * SECRETS_BACKEND=memory             → InMemorySecretStore
      * SECRETS_BACKEND=postgres (default) → PostgresSecretStore using SECRETS_PG_URL
                                              or POSTGRES_URL or a sane local default
    """
    backend = os.environ.get("SECRETS_BACKEND", "postgres").lower()
    if backend == "memory":
        return InMemorySecretStore(seed_audiences=seed_audiences)
    dsn = (
        os.environ.get("SECRETS_PG_URL")
        or os.environ.get("POSTGRES_URL")
        or "postgresql://soc:soc@localhost:5432/soc_checkpoint"
    )
    return PostgresSecretStore(
        dsn=dsn,
        seed_audiences=seed_audiences,
        on_rotate=on_rotate,
    )
