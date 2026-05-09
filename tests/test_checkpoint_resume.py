"""
Checkpoint resume tests for AsyncRedisSaver wrapping.

Two layers:

1. Pure unit tests for the ``CheckpointerFactory`` policy logic (TTL math,
   per-tenant overrides, cache keys). These run without Redis.

2. Integration tests (``@pytest.mark.integration``) that exercise the real
   AsyncRedisSaver against a running Redis. Skipped unless ``REDIS_URL``
   is reachable. Run with:

       make dev               # starts redis on :6379
       uv run pytest tests/test_checkpoint_resume.py -v -m integration
"""

from __future__ import annotations

import os
import uuid

import pytest

from services._runtime.checkpoint_redis_ttl import (
    CheckpointerFactory,
    _read_ttl_seconds,
    _ttl_minutes,
)

# ---------------------------------------------------------------------------
# Unit: TTL helpers
# ---------------------------------------------------------------------------


def test_ttl_minutes_rounds_up_to_avoid_truncation_under_a_day() -> None:
    # 24h must stay 24h, not 23h59m due to integer truncation.
    assert _ttl_minutes(24 * 60 * 60) == 24 * 60
    # Sub-minute inputs round up to 1 minute (floor of zero is unsafe).
    assert _ttl_minutes(30) == 1
    # Exact minute multiples stay exact.
    assert _ttl_minutes(5 * 60) == 5


def test_read_ttl_seconds_falls_back_when_invalid(monkeypatch) -> None:
    monkeypatch.setenv("CHECKPOINT_TTL_SEC", "not-a-number")
    assert _read_ttl_seconds() == 30 * 24 * 60 * 60   # default 30 days

    monkeypatch.setenv("CHECKPOINT_TTL_SEC", "0")
    assert _read_ttl_seconds() == 30 * 24 * 60 * 60   # zero is invalid → default

    monkeypatch.setenv("CHECKPOINT_TTL_SEC", "3600")
    assert _read_ttl_seconds() == 3600


def test_read_ttl_seconds_uses_default_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("CHECKPOINT_TTL_SEC", raising=False)
    assert _read_ttl_seconds() == 30 * 24 * 60 * 60


# ---------------------------------------------------------------------------
# Unit: CheckpointerFactory caching policy
# ---------------------------------------------------------------------------


def test_factory_resolves_default_ttl_for_unknown_tenant() -> None:
    f = CheckpointerFactory("redis://nonexistent:6379/0", default_ttl_seconds=600)
    assert f.default_ttl_seconds == 600
    # Internal _ttl_for: uses default for unknown tenants.
    assert f._ttl_for("acme") == 600
    assert f._ttl_for(None) == 600


def test_factory_applies_per_tenant_override() -> None:
    f = CheckpointerFactory(
        "redis://nonexistent:6379/0",
        default_ttl_seconds=600,
        tenant_ttl_overrides={"regulated-co": 90 * 24 * 60 * 60},
    )
    assert f._ttl_for("regulated-co") == 90 * 24 * 60 * 60
    assert f._ttl_for("acme") == 600


def test_set_tenant_override_invalidates_cache() -> None:
    f = CheckpointerFactory("redis://nonexistent:6379/0", default_ttl_seconds=600)
    # Pre-populate the cache with a sentinel so we can detect invalidation.
    bumped_ttl = 9000
    cache_key = CheckpointerFactory._cache_key(bumped_ttl)
    f._cache[cache_key] = "sentinel"
    f.set_tenant_override("acme", bumped_ttl)
    # The override-bound entry must have been dropped so the next get_checkpointer
    # builds a fresh saver with the new TTL.
    assert cache_key not in f._cache


def test_set_tenant_override_rejects_non_positive() -> None:
    f = CheckpointerFactory("redis://nonexistent:6379/0", default_ttl_seconds=600)
    with pytest.raises(ValueError):
        f.set_tenant_override("acme", 0)
    with pytest.raises(ValueError):
        f.set_tenant_override("acme", -1)


# ---------------------------------------------------------------------------
# Integration: real Redis required
# ---------------------------------------------------------------------------


def _redis_url() -> str:
    return os.environ.get("REDIS_URL", "redis://localhost:6379/0")


async def _redis_reachable(url: str) -> bool:
    try:
        import redis.asyncio as aioredis

        client = aioredis.from_url(url, decode_responses=True)
        try:
            await client.ping()
            return True
        finally:
            await client.aclose()
    except Exception:
        return False


@pytest.mark.integration
async def test_factory_returns_working_async_redis_saver() -> None:
    """A new saver round-trips through Redis without error (sanity check)."""
    url = _redis_url()
    if not await _redis_reachable(url):
        pytest.skip(f"Redis not reachable at {url}")

    factory = CheckpointerFactory(url, default_ttl_seconds=120)
    saver = await factory.get_checkpointer()
    # Library-level smoke: the saver is configured with our TTL value, in minutes.
    assert saver.ttl_config["default_ttl"] == _ttl_minutes(120)
    assert saver.ttl_config["refresh_on_read"] is True


@pytest.mark.integration
async def test_factory_caches_per_ttl_value() -> None:
    """
    Two tenants sharing the default TTL get the same saver instance;
    a tenant with an override gets a distinct saver.
    """
    url = _redis_url()
    if not await _redis_reachable(url):
        pytest.skip(f"Redis not reachable at {url}")

    factory = CheckpointerFactory(
        url,
        default_ttl_seconds=600,
        tenant_ttl_overrides={"regulated-co": 7200},
    )
    a = await factory.get_checkpointer("acme")
    b = await factory.get_checkpointer("globex")
    c = await factory.get_checkpointer("regulated-co")

    assert a is b           # same TTL → same instance
    assert a is not c       # different TTL → different instance


@pytest.mark.integration
async def test_graph_resume_after_simulated_worker_crash() -> None:
    """
    Simulates the redelivery + checkpoint-resume contract end-to-end:

      1. A "first worker" advances the graph through the first node and
         persists state to the checkpointer keyed by ``thread_id``.
      2. The first worker is discarded mid-graph (simulating kill -9).
      3. A "second worker" picks up the same ``thread_id`` and resumes —
         the first node MUST NOT re-run.

    We use a minimal two-node toy graph here because the full SOC
    triage pipeline requires LLM credentials to run. The contract under
    test is the checkpointer wiring, which is graph-shape-agnostic.
    """
    url = _redis_url()
    if not await _redis_reachable(url):
        pytest.skip(f"Redis not reachable at {url}")

    from typing import TypedDict

    from langgraph.graph import END, StateGraph

    factory = CheckpointerFactory(url, default_ttl_seconds=300)

    class S(TypedDict, total=False):
        n: int
        history: list[str]

    # We share this counter across the two graph instances so we can assert
    # the first node does NOT execute a second time on resume.
    first_node_calls = {"count": 0}

    def first(state: S) -> S:
        first_node_calls["count"] += 1
        return {"n": (state.get("n") or 0) + 1, "history": ["first"]}

    def second(state: S) -> S:
        return {"n": (state.get("n") or 0) + 1, "history": [*state.get("history", []), "second"]}

    def make_graph(checkpointer):
        g = StateGraph(S)
        g.add_node("first", first)
        g.add_node("second", second)
        g.set_entry_point("first")
        g.add_edge("first", "second")
        g.add_edge("second", END)
        return g.compile(checkpointer=checkpointer)

    thread_id = f"test-resume-{uuid.uuid4()}"
    saver = await factory.get_checkpointer()

    # Worker 1: run through "first" only (interrupt before "second").
    graph_1 = make_graph(saver)
    config = {"configurable": {"thread_id": thread_id}}
    async for _ in graph_1.astream(
        {"n": 0, "history": []},
        config=config,
        stream_mode="values",
    ):
        # Stop after the first node has produced a checkpoint.
        last = await saver.aget(config)
        if last and "first" in (last.get("channel_values", {}).get("history") or []):
            break

    # Discard graph_1 entirely — simulates worker death.
    del graph_1
    assert first_node_calls["count"] == 1

    # Worker 2: a fresh compilation, resuming the same thread_id.
    graph_2 = make_graph(saver)
    final = None
    async for chunk in graph_2.astream(None, config=config, stream_mode="values"):
        final = chunk

    assert final is not None
    # Must reach completion via second node...
    assert "second" in final["history"]
    # ...and the first node must NOT have re-run on resume.
    assert first_node_calls["count"] == 1, (
        "first node ran a second time — checkpointer is not actually resuming"
    )
