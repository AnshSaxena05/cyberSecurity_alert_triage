# services/_runtime

Architecture-2 runtime infrastructure. Single-owner package. Each helper is
small, async-first, and individually tested.

## Inventory

| Module | Purpose | Status |
|--------|---------|--------|
| `tenant.py` | Single accessor `get_tenant_id(ctx)` — reads only from verified JWT context. Direct payload reads forbidden by `scripts/lint_tenant_id.py`. | implemented |
| `event_seq.py` | `INCR seq:{alert_id}` helper for monotonic per-alert event ordering. Used by every event publisher and the DO snapshot read. | implemented |
| `cancel.py` | `mark_cancelled` / `is_cancelled` with 5-second debounce grace window. Worker reads at every LLM-call boundary. | implemented |
| `jwt_service.py` | HS256 sign/verify with audience enforcement, per-batch verify cache, and revocation deny-list check. | implemented |
| `nats_broker.py` | NATS JetStream client init (mirrors Redis pattern), publishers with ack policy, pull-consumer scaffolding. | skeleton |
| `ingest_reconciler.py` | Background loop scanning `pending_alert:*` and retrying NATS publish. | TODO |
| `checkpoint_redis_ttl.py` | Wrapper around `AsyncRedisSaver` adding per-tenant TTL. | TODO |
| `jwt_bootstrap.py` | Vault AppRole exchange to fetch initial HS256 secret on worker boot. | TODO |
| `secret_publisher.py` | Standalone service orchestrating 24h secret rotation. | TODO |
| `triage_worker.py` | Long-running NATS pull-consumer. Verifies token, calls `run_triage`, publishes events. | TODO |
| `audit.py` | Raw-payload retention; coercion-trace recording; weekly hash-chained S3 dumps. | TODO |
| `otel.py` | OpenTelemetry init; trace-id propagation through NATS headers. | TODO |

## Rules for contributors

1. No module may import from `app/*`, `agents/*`, `evaluation/*`. One-way
   dependency: app/agents/services_top_level depend on `_runtime`, never the
   reverse.
2. Every public function ships with a docstring stating its concurrency
   contract (idempotent? safe to call from multiple workers? requires Redis?).
3. Tests for `_runtime` live in `tests/test_runtime_*.py` and must pass
   without external services for unit tests. Integration tests can require
   Redis/NATS via the `docker-compose.dev.yml` stack.
4. Custom code in this package counts against the wrapper budget tracked in
   the architecture plan. If the package exceeds 1500 LoC total, revisit
   whether to extract it into a separate library.
