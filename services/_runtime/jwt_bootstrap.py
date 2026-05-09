"""
JWT bootstrap.

A process that mints or verifies HS256 service tokens needs the current
secret bundle for its audience(s) on boot, plus a way to refresh that
bundle when the rotator publishes a new one. This module wires:

    SecretStore (Postgres) → in-process bundle cache → JWTService instances

Any number of ``JWTService`` instances per process can pull from the same
``ServiceTokenAuthority``; each verifies/mints for one audience but
shares a connection pool.

Usage in a worker / API process::

    authority = await ServiceTokenAuthority.start(
        store=secret_store_from_env(),
        audiences=("worker", "ingest"),
    )
    worker_jwt = authority.jwt_for("worker")
    ingest_jwt = authority.jwt_for("ingest")

    # ... use worker_jwt.verify(token) or ingest_jwt.mint(...) ...

    await authority.stop()

If the secret store is unreachable on boot, the authority logs and falls
back to a single in-memory bundle so the process can still start in
degraded mode (every issued token will be invalid the moment the store
returns, which is the intended fail-loud behaviour).
"""

from __future__ import annotations

import asyncio

import structlog

from services._runtime.jwt_service import JWTService, SecretBundle
from services._runtime.secret_store import (
    InMemorySecretStore,
    SecretStore,
    secret_store_from_env,
)

logger = structlog.get_logger(__name__)


class ServiceTokenAuthority:
    """In-process cache of secret bundles + JWTService instances per audience."""

    def __init__(
        self,
        store: SecretStore,
        audiences: tuple[str, ...],
    ) -> None:
        self._store = store
        self._audiences = tuple(audiences)
        self._bundles: dict[str, SecretBundle] = {}
        self._services: dict[str, JWTService] = {}
        self._refresh_lock = asyncio.Lock()

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------

    @classmethod
    async def start(
        cls,
        *,
        store: SecretStore | None = None,
        audiences: tuple[str, ...] = ("worker", "ingest", "gateway"),
        revoked_jti_checker=None,
    ) -> ServiceTokenAuthority:
        if store is None:
            # Default: read SECRETS_BACKEND, defer rotation watcher to caller.
            store = secret_store_from_env(seed_audiences=audiences)

        authority = cls(store=store, audiences=audiences)
        try:
            await store.initialize()
        except Exception as exc:
            logger.warning(
                "service_token_authority_store_init_failed_degraded_mode",
                error=str(exc),
            )
            # Swap to an in-memory store so the process can still boot.
            authority._store = InMemorySecretStore(seed_audiences=audiences)
            await authority._store.initialize()

        await authority._load_all()

        # Wire JWTService per audience. The bundle_provider closure reads
        # the LATEST in-memory bundle on every mint/verify, so a refresh
        # picks up new secrets without reconstructing the service.
        for aud in audiences:
            authority._services[aud] = JWTService(
                audience=aud,
                bundle_provider=authority._make_provider(aud),
                revoked_jti_checker=revoked_jti_checker,
            )

        return authority

    async def stop(self) -> None:
        await self._store.close()

    # -----------------------------------------------------------------
    # Public access
    # -----------------------------------------------------------------

    def jwt_for(self, audience: str) -> JWTService:
        if audience not in self._services:
            raise KeyError(f"no JWTService for audience {audience!r}")
        return self._services[audience]

    def bundle_for(self, audience: str) -> SecretBundle:
        b = self._bundles.get(audience)
        if b is None:
            raise KeyError(f"no bundle for audience {audience!r}")
        return b

    async def refresh(self, audience: str | None = None) -> None:
        """
        Reload one (or all) bundles from the store.

        Call from a rotation-notify callback, or on a periodic timer if
        the store doesn't push notifications.
        """
        async with self._refresh_lock:
            if audience is None:
                await self._load_all()
                return
            if audience not in self._audiences:
                logger.warning("service_token_authority_unknown_audience", audience=audience)
                return
            try:
                self._bundles[audience] = await self._store.get_bundle(audience)
                logger.info("service_token_bundle_refreshed", audience=audience)
            except Exception as exc:
                logger.warning(
                    "service_token_bundle_refresh_failed",
                    audience=audience,
                    error=str(exc),
                )

    # -----------------------------------------------------------------
    # Internals
    # -----------------------------------------------------------------

    async def _load_all(self) -> None:
        for aud in self._audiences:
            try:
                self._bundles[aud] = await self._store.get_bundle(aud)
            except Exception as exc:
                logger.warning(
                    "service_token_bundle_load_failed",
                    audience=aud,
                    error=str(exc),
                )

    def _make_provider(self, audience: str):
        # Closure captures `self` and `audience`; reads the latest bundle
        # on every call. JWTService caches verify results per-jti so this
        # call is on the cold path only.
        def _provider() -> SecretBundle:
            bundle = self._bundles.get(audience)
            if bundle is None:
                raise KeyError(f"bundle for audience {audience!r} not yet loaded")
            return bundle

        return _provider
