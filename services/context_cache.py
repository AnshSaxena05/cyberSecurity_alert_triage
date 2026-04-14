"""
Context Cache — Redis-backed IOC result cache.

Prevents redundant API calls to Threat Intel and SIEM sources for the same
IOC within a 15-minute window. A cache hit returns the stored result
immediately, preserving the tool budget for novel queries.

Cache key: sha256(tool_name + canonical_params_json)
TTL: configurable (default 900s = 15 minutes per architecture spec)
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def _make_key(tool_name: str, params: dict[str, Any]) -> str:
    canonical = json.dumps({"tool": tool_name, "params": params}, sort_keys=True)
    return "soc:cache:" + hashlib.sha256(canonical.encode()).hexdigest()


class ContextCache:
    def __init__(self, redis_url: str, ttl_seconds: int = 900, enabled: bool = True) -> None:
        self._ttl = ttl_seconds
        self._enabled = enabled
        self._client = None
        if enabled:
            try:
                import redis.asyncio as aioredis
                self._client = aioredis.from_url(redis_url, decode_responses=True)
            except Exception as exc:
                logger.warning("cache_init_failed", error=str(exc), fallback="disabled")
                self._enabled = False

    async def get(self, tool_name: str, params: dict[str, Any]) -> dict[str, Any] | None:
        if not self._enabled or self._client is None:
            return None
        key = _make_key(tool_name, params)
        try:
            raw = await self._client.get(key)
            if raw:
                logger.debug("cache_hit", tool=tool_name, key=key[:16])
                return json.loads(raw)
        except Exception as exc:
            logger.warning("cache_get_error", error=str(exc))
        return None

    async def set(self, tool_name: str, params: dict[str, Any], result: dict[str, Any]) -> None:
        if not self._enabled or self._client is None:
            return
        key = _make_key(tool_name, params)
        try:
            await self._client.setex(key, self._ttl, json.dumps(result))
            logger.debug("cache_set", tool=tool_name, ttl=self._ttl)
        except Exception as exc:
            logger.warning("cache_set_error", error=str(exc))

    async def invalidate(self, tool_name: str, params: dict[str, Any]) -> None:
        if not self._enabled or self._client is None:
            return
        key = _make_key(tool_name, params)
        try:
            await self._client.delete(key)
        except Exception as exc:
            logger.warning("cache_invalidate_error", error=str(exc))

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()


_cache_instance: ContextCache | None = None


def get_cache() -> ContextCache:
    global _cache_instance
    if _cache_instance is None:
        from app.config import get_settings
        s = get_settings()
        _cache_instance = ContextCache(
            redis_url=s.redis_url,
            ttl_seconds=s.cache_ttl_seconds,
            enabled=s.cache_enabled,
        )
    return _cache_instance
