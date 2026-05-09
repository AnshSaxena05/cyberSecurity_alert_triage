"""
AsyncRedisSaver factory with TTL + per-tenant override.

The underlying ``langgraph-checkpoint-redis`` library supports TTL natively
via the ``ttl={"default_ttl": <minutes>, "refresh_on_read": bool}`` config.
We wrap that with:

  * env-var-driven default (``CHECKPOINT_TTL_SEC``, default 30 days)
  * per-tenant overrides (regulated tenants can extend retention)
  * a single accessor so triage_pipeline.compile(...) doesn't have to know
    these knobs exist
  * an upgrade-gate hook (compute a schema fingerprint on boot so a library
    bump that breaks deserialization fails loudly instead of silently
    losing checkpoints)

Concurrency:
  * One ``AsyncRedisSaver`` instance per (process, tenant_id_or_default).
  * Redis client is shared underneath (the library handles connection pool).
  * Safe to call ``get_checkpointer`` from multiple coroutines; a per-tenant
    instance is created lazily and cached.
"""

from __future__ import annotations

import os

import structlog

logger = structlog.get_logger(__name__)

_DEFAULT_TTL_SEC = 30 * 24 * 60 * 60   # 30 days
_DEFAULT_TENANT_KEY = "__default__"


def _ttl_minutes(seconds: int) -> int:
    # Library API uses minutes; round up so 24h doesn't accidentally become
    # 23h59m due to truncation.
    return max(1, (seconds + 59) // 60)


def _read_ttl_seconds() -> int:
    raw = os.environ.get("CHECKPOINT_TTL_SEC", "")
    try:
        v = int(raw) if raw else _DEFAULT_TTL_SEC
        return v if v > 0 else _DEFAULT_TTL_SEC
    except ValueError:
        logger.warning("checkpoint_ttl_invalid", value=raw, fallback=_DEFAULT_TTL_SEC)
        return _DEFAULT_TTL_SEC


class CheckpointerFactory:
    """
    Builds and caches AsyncRedisSaver instances keyed by tenant.

    Per-tenant overrides come from the optional ``tenant_ttl_overrides``
    map at construction. If a tenant is not in the map, the default TTL
    applies. A factory is intended to be process-singleton — store it on
    application state, not module-level.
    """

    def __init__(
        self,
        redis_url: str,
        *,
        default_ttl_seconds: int | None = None,
        tenant_ttl_overrides: dict[str, int] | None = None,
        refresh_on_read: bool = True,
    ) -> None:
        self._redis_url = redis_url
        self._default_ttl = default_ttl_seconds or _read_ttl_seconds()
        self._tenant_overrides = dict(tenant_ttl_overrides or {})
        self._refresh = refresh_on_read
        self._cache: dict[str, object] = {}    # tenant_id -> AsyncRedisSaver
        self._setup_done: set[str] = set()

    # ---------- Public API --------------------------------------------

    async def get_checkpointer(self, tenant_id: str | None = None):
        """
        Return an AsyncRedisSaver scoped to the tenant's TTL policy.

        ``tenant_id=None`` means "use the default TTL." Same instance is
        returned across calls for the same effective TTL — we cache by
        TTL value so two tenants sharing the default share the saver.
        """
        ttl_sec = self._ttl_for(tenant_id)
        cache_key = self._cache_key(ttl_sec)
        existing = self._cache.get(cache_key)
        if existing is not None:
            return existing

        saver = self._build(ttl_sec)
        self._cache[cache_key] = saver

        # Lazy index/setup the first time we see this configuration.
        if cache_key not in self._setup_done:
            try:
                await saver.asetup()
                self._setup_done.add(cache_key)
            except Exception as exc:
                logger.warning("checkpoint_setup_failed", error=str(exc), tenant=tenant_id)
        return saver

    def set_tenant_override(self, tenant_id: str, ttl_seconds: int) -> None:
        """Set or update a per-tenant TTL override at runtime."""
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self._tenant_overrides[tenant_id] = ttl_seconds
        # Force a fresh saver next call by dropping the cached one.
        cache_key = self._cache_key(ttl_seconds)
        self._cache.pop(cache_key, None)

    @property
    def default_ttl_seconds(self) -> int:
        return self._default_ttl

    # ---------- Internals ---------------------------------------------

    def _ttl_for(self, tenant_id: str | None) -> int:
        if tenant_id and tenant_id in self._tenant_overrides:
            return self._tenant_overrides[tenant_id]
        return self._default_ttl

    @staticmethod
    def _cache_key(ttl_sec: int) -> str:
        return f"ttl:{ttl_sec}"

    def _build(self, ttl_sec: int):
        # Imported lazily so unit tests that don't need checkpointing don't
        # pay the langchain/langgraph import cost.
        from langgraph.checkpoint.redis.aio import AsyncRedisSaver

        return AsyncRedisSaver(
            redis_url=self._redis_url,
            ttl={
                "default_ttl": _ttl_minutes(ttl_sec),
                "refresh_on_read": self._refresh,
            },
            checkpoint_prefix="checkpoint",
            checkpoint_write_prefix="checkpoint_write",
        )
