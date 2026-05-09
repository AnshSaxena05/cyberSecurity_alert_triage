# SOC Triage Gateway (Cloudflare Durable Objects)

Holds the analysts' WebSockets at the edge. The Python/FastAPI backend never
sees a public TCP connection.

## Architecture: reverse-push fan-out

This gateway uses **Option 1** from the architecture trade-off note. The DO
does NOT subscribe to NATS. Instead:

```
Browser
  │  wss://gateway.example.com/ws?t=<60s ticket>
  ▼
Cloudflare Worker → AnalystSession DO (one per analyst session)
  │     ▲
  │     │ (3) HTTP POST /push?do=<id>   (auth: gateway service JWT)
  │     │
  │     │
  │   Cloudflare Worker (same process, /push route)
  │     ▲
  │     │ (2) HTTP POST <bff>/push…
  │     │
  │   BFF Event Fan-Out Service (Node, holds 1 NATS conn per process)
  │     ▲
  │     │ (1) NATS subscribe on triage.events.v1.>, triage.cancel.v1.>,
  │     │                          auth.revocations.v1.>
  │     │
  │   NATS  ←──  Python worker publishes phase / token / cancel / revoke
  ▼
browser WS frame
```

## DO responsibilities

1. **Redeem the WS ticket** against `/api/ws/redeem` on the BFF (gets `user_id`,
   `tenant_id`, `role`).
2. **Register/unregister** with the BFF's watcher registry on `watch`/`unwatch`
   from the browser. Routes used:
   - `POST /api/internal/watch` (registers `{do_id, user_id, tenant_id, alert_id, push_url}`)
   - `POST /api/internal/unwatch`
   - `POST /api/internal/disconnect` (on WS close)
3. **Receive HTTP POSTs** at `/push?do=<id>` from the BFF fan-out service.
   The Worker resolves `do_id` to the DO instance and forwards via DO RPC.
4. **Forward to the WebSocket**: the DO calls `state.getWebSockets()` and emits
   the event JSON to every active WS.
5. **Debounced cancel-on-close**: 5-second grace window; if the user reopens
   their tab in time, abort. Otherwise POST `/api/internal/cancel` so the BFF
   publishes `triage.cancel.v1.{tenant}.{alert}` on NATS for the worker.

## Why this beats DO-subscribes-to-NATS

- **Eviction safety is trivial**: an inbound HTTP POST wakes the DO; a fully
  evicted DO returns 410, the fan-out prunes that watcher entry, and the
  browser's reconnect creates a new DO with a new id.
- **No long-lived outbound NATS connection inside V8 isolates** — sidesteps
  the unverified `nats.ws` survival-under-eviction concern.
- **NATS stays inside the trust boundary**; the broker is never exposed past
  the BFF.

## Local dev

```bash
cd gateway
npm install        # not yet done in this scaffold
wrangler secret put GATEWAY_SERVICE_TOKEN_SECRET  # paste the value from Postgres
npm run dev        # wrangler dev --local on :8787
```

You'll need:
- BFF on `:3000` (`cd ../frontend && npm run dev`)
- NATS on `:4222`
- Redis on `:6379`
- Postgres on `:5432` with the `service_secrets` row for audience=`gateway`
  (created by `services/_runtime/secret_store.py` on FastAPI boot)
- FastAPI on `:8000` (`make api` from repo root)

## Layout

```
gateway/
  src/
    index.ts              Worker entry: routes /ws, /push, /healthz
    durable-object.ts     AnalystSession class
    snapshot-subscribe.ts read snapshot before registering a watch
    nats-bridge.ts        deprecated marker — delete after one release
    jwt.ts                Web-Crypto HS256 sign/verify (no library dep)
    types.ts              shared interfaces
  wrangler.toml
  package.json
  tsconfig.json
```

## Eviction & hibernation

Cloudflare Hibernation API keeps the WebSocket alive across idle. When the
BFF POSTs an event, CF wakes the DO; the DO calls `state.getWebSockets()` to
recover the WS handles and forwards. On full eviction the DO is gone and
the WS is severed; the browser sees a disconnect and reconnects with a fresh
ticket → new DO id → re-registration.

The DO holds no in-RAM state that requires reconstruction — the only persisted
fact is "this DO is registered as a watcher for these alerts," which lives in
the BFF's Redis registry. After eviction the registry entries time out via TTL
and the new DO instance re-registers on its first `watch` message.
