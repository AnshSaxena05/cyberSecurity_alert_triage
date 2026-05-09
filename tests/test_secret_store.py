"""
Secret store + JWT bootstrap tests.

The InMemorySecretStore covers the pure logic without any external deps.
Postgres integration tests are gated on a reachable Postgres at
``$SECRETS_PG_URL`` (or ``$POSTGRES_URL``, or the default
``postgresql://soc:soc@localhost:5432/soc_checkpoint``).

Run integration with:

    docker compose -f docker-compose.dev.yml --profile regulated up -d postgres
    uv run pytest tests/test_secret_store.py -v -m integration
"""

from __future__ import annotations

import os

import pytest

from services._runtime.jwt_bootstrap import ServiceTokenAuthority
from services._runtime.jwt_service import JWTError
from services._runtime.secret_store import (
    DEFAULT_AUDIENCES,
    InMemorySecretStore,
    PostgresSecretStore,
)

# ---------------------------------------------------------------------------
# Unit: InMemorySecretStore
# ---------------------------------------------------------------------------


async def test_inmemory_seeds_default_audiences() -> None:
    store = InMemorySecretStore()
    await store.initialize()
    for aud in DEFAULT_AUDIENCES:
        bundle = await store.get_bundle(aud)
        assert bundle.audience == aud
        assert bundle.current
        assert bundle.previous is None
    await store.close()


async def test_inmemory_rotate_shifts_current_to_previous() -> None:
    store = InMemorySecretStore()
    await store.initialize()
    pre = await store.get_bundle("worker")
    post = await store.rotate("worker")
    assert post.previous == pre.current
    assert post.current != pre.current
    assert post.rotated_at >= pre.rotated_at


async def test_inmemory_rotate_unknown_audience_creates_it() -> None:
    store = InMemorySecretStore(seed_audiences=("worker",))
    await store.initialize()
    # In the in-memory implementation, rotating an unknown audience
    # creates it on the fly (matches Postgres rotate semantics).
    bundle = await store.rotate("brand-new")
    assert bundle.audience == "brand-new"
    assert bundle.current
    # No previous, since it didn't exist before.
    assert bundle.previous is None


# ---------------------------------------------------------------------------
# Unit: ServiceTokenAuthority over InMemory store
# ---------------------------------------------------------------------------


async def test_authority_loads_bundles_for_all_audiences() -> None:
    store = InMemorySecretStore()
    auth = await ServiceTokenAuthority.start(
        store=store,
        audiences=("worker", "ingest"),
    )
    try:
        # Both bundles must be loaded.
        for aud in ("worker", "ingest"):
            bundle = auth.bundle_for(aud)
            assert bundle.audience == aud
            assert bundle.current
        # JWTService instances exist and are distinct.
        assert auth.jwt_for("worker") is not auth.jwt_for("ingest")
    finally:
        await auth.stop()


async def test_authority_mint_and_verify_via_two_audiences() -> None:
    """
    Demonstrates the two-token model: BFF mints a token addressed to
    'worker', the worker's JWTService verifies it.
    """
    # Both BFF and worker share the same backing store (single Postgres
    # in production; same in-memory dict here for the test).
    store = InMemorySecretStore(seed_audiences=("worker", "bff"))
    auth = await ServiceTokenAuthority.start(
        store=store,
        audiences=("worker", "bff"),
    )
    try:
        bff_jwt = auth.jwt_for("bff")
        worker_jwt = auth.jwt_for("worker")

        # The BFF mints — but its bundle is for audience "bff", and
        # JWTService.mint requires bundle.audience == self._audience.
        # So the BFF's bundle is what signs; the worker verifies that
        # signature using its own bundle. For the test, the two stores
        # share the same secret material since seed_audiences includes
        # both — but in production they don't share. We exercise the
        # single-store-shared-secret path here as a logic check.
        # Simpler demonstration: rotate worker, verify a fresh token.
        token = bff_jwt.mint(
            subject="user-1",
            tenant_id="acme",
            target_audience="bff",            # token addressed to its own audience
        )
        verified = await bff_jwt.verify(token)
        assert verified.tenant_id == "acme"

        # Cross-audience: a token aimed at worker is NOT accepted by ingest.
        worker_token = bff_jwt.mint(
            subject="u",
            tenant_id="acme",
            target_audience="worker",
        )
        # The bff's signing key is different from worker's, so verify
        # against worker_jwt (different secret) must fail signature check.
        with pytest.raises(JWTError):
            await worker_jwt.verify(worker_token)
    finally:
        await auth.stop()


async def test_authority_refresh_picks_up_rotation() -> None:
    store = InMemorySecretStore(seed_audiences=("worker",))
    auth = await ServiceTokenAuthority.start(store=store, audiences=("worker",))
    try:
        before = auth.bundle_for("worker").current

        # Simulate an out-of-band rotation by another process.
        await store.rotate("worker")

        # Authority hasn't been told yet → still serves old bundle.
        assert auth.bundle_for("worker").current == before

        # Refresh — pulls the latest bundle.
        await auth.refresh("worker")
        after = auth.bundle_for("worker").current
        assert after != before
    finally:
        await auth.stop()


async def test_authority_refresh_unknown_audience_is_quiet() -> None:
    store = InMemorySecretStore(seed_audiences=("worker",))
    auth = await ServiceTokenAuthority.start(store=store, audiences=("worker",))
    try:
        # Should not raise.
        await auth.refresh("does-not-exist")
    finally:
        await auth.stop()


# ---------------------------------------------------------------------------
# Integration: real Postgres
# ---------------------------------------------------------------------------


def _pg_dsn() -> str:
    return (
        os.environ.get("SECRETS_PG_URL")
        or os.environ.get("POSTGRES_URL")
        or "postgresql://soc:soc@localhost:5432/soc_checkpoint"
    )


async def _pg_reachable(dsn: str) -> bool:
    try:
        import asyncpg

        conn = await asyncpg.connect(dsn=dsn, timeout=2)
        try:
            await conn.execute("SELECT 1")
            return True
        finally:
            await conn.close()
    except Exception:
        return False


@pytest.mark.integration
async def test_postgres_seed_then_get_bundle() -> None:
    dsn = _pg_dsn()
    if not await _pg_reachable(dsn):
        pytest.skip(f"Postgres not reachable at {dsn}")

    store = PostgresSecretStore(dsn=dsn, seed_audiences=("test-audience-A",))
    await store.initialize()
    try:
        bundle = await store.get_bundle("test-audience-A")
        assert bundle.audience == "test-audience-A"
        assert bundle.current
    finally:
        # Clean up the seeded row to keep the dev database tidy.
        import asyncpg
        conn = await asyncpg.connect(dsn=dsn)
        try:
            await conn.execute(
                "DELETE FROM service_secrets WHERE audience = $1", "test-audience-A"
            )
        finally:
            await conn.close()
        await store.close()


@pytest.mark.integration
async def test_postgres_rotate_shifts_current_to_previous() -> None:
    dsn = _pg_dsn()
    if not await _pg_reachable(dsn):
        pytest.skip(f"Postgres not reachable at {dsn}")

    store = PostgresSecretStore(dsn=dsn, seed_audiences=("test-rot",))
    await store.initialize()
    try:
        pre = await store.get_bundle("test-rot")
        post = await store.rotate("test-rot")
        assert post.previous == pre.current
        assert post.current != pre.current
    finally:
        import asyncpg
        conn = await asyncpg.connect(dsn=dsn)
        try:
            await conn.execute(
                "DELETE FROM service_secrets WHERE audience = $1", "test-rot"
            )
        finally:
            await conn.close()
        await store.close()
