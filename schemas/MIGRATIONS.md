# Schema Migrations

Authoritative log of breaking schema changes per version bump.

## Versioning rule

- Frozen-on-ship: once `schemas/vN/` is deployed, files in that directory are never edited.
- Breaking changes (rename, remove, type-narrow): copy `schemas/vN/` → `schemas/vN+1/`, edit there.
- Additive changes (new optional field): also require a version bump if any consumer relies on the absence of a field; otherwise can land in-place during the pre-ship window only.
- Subject naming: every NATS subject embeds the schema version, e.g. `alerts.v1.{tenant}.{source}.{id}`. Producers publish to the latest they speak; consumers subscribe to all versions they understand.

## Cutover sequence (zero-downtime)

1. Add `schemas/vN+1/` with the new shape. Update `schemas/_compat_test.py` for the new pair.
2. Deploy worker N+1 code that publishes vN+1 AND consumes both vN and vN+1.
3. Wait for the vN stream to drain (bounded by `max_age`, default 24h).
4. Remove the vN publish path; keep vN consume one more deploy as safety net.
5. Remove vN consume + delete `schemas/vN/` after a sprint.

## Compatibility CI rules

- A PR that removes or renames a field in any `schemas/v*` directory hard-fails CI.
- A PR that introduces a new version must also update this file with the rationale and the cutover plan.
- A PR that only adds optional fields with safe defaults can land without a new version.

---

## Version history

### v1.0.0 (initial)

First versioned schema. Extracted from `app/models.py` at commit-time of the
Architecture-2 rollout. `app/models.py` becomes a re-export shim; new code
should import from `schemas.v1` directly.

New in v1 (not present in pre-versioning code):

- `NormalizedAlert.tenant_id: str | None` — multi-tenancy field, populated
  authoritatively from the verified service JWT.
- `NormalizedAlert.coerced_by_llm: bool` and `coercion_trace_id: str | None`
  — audit-trail flags for the auto-ingest LLM coercion path.
- `TriageVerdict.tenant_id: str | None` — same multi-tenancy story.
- `TriageVerdict.status: str | None` — populated as `"cancelled"` when worker
  stops due to a `triage.cancel` signal; `None` for normal completion.
- `schemas/v1/triage_event.py` — new envelopes (`PhaseEvent`, `TokenEvent`,
  `TriageCancelEvent`) for the NATS event stream. These do not exist in the
  pre-versioning code.
