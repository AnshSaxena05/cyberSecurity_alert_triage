"""
Architecture-2 runtime infrastructure.

This package holds the small, single-purpose helpers that wrap NATS, Redis,
JWT, OTel, and the runtime guarantees the canonical pipeline relies on.

Conventions (read before adding anything):

- Each module is small and single-purpose. If a module grows past ~200 LoC,
  split it.
- All helpers are async-first to match the existing FastAPI / LangGraph stack.
- Redis client init mirrors the pattern in services/context_cache.py — never
  invent a new pattern.
- No module here may import from app/* or agents/* (one-way dependency).
- Every module ships with property/integration tests under tests/.

See [services/_runtime/README.md](README.md) for inventory + ownership.
"""
