"""
Versioned, frozen Pydantic schemas for the SOC triage system.

Layout:
    schemas/_common/    Stable shared types (enums, OCSF building blocks).
                        One-way dependency: _common does NOT import from any v*.
    schemas/v1/         Frozen v1 models. Never edited once shipped.
    schemas/v2/         (future) Frozen v2 models when a breaking change ships.

Versioning rule: producers publish to the latest version they speak; consumers
subscribe to all versions they understand. See schemas/MIGRATIONS.md.
"""
