# SOC Triage BFF (Backend-for-Frontend)

The Architecture-2 BFF lives here. It is the *only* thing the browser talks to.

What it owns:
- **Auth**: `/api/auth/login`, `/refresh`, `/logout`. Issues a 15-minute access JWT (in-memory in the browser) plus a 7-day opaque refresh token (HttpOnly cookie + Redis-backed session).
- **Service tokens**: mints short-lived HS256 service JWTs targeted at FastAPI (`ingest`), the worker (`worker`), and the gateway (`gateway`). The browser never sees these.
- **WebSocket tickets**: `/api/ws/ticket` issues a 60-second single-use ticket that the browser exchanges with the Cloudflare Durable Object on connect. `/api/ws/redeem` consumes the ticket on the DO's behalf.
- **Ingest forwarder**: `/api/ingest` receives client-uploaded alert JSON, attaches the internal service JWT, and forwards to FastAPI.
- **Snapshot proxy**: `/api/alerts/{id}/snapshot` so the DO can read alert state without ever talking to FastAPI directly (FastAPI stays invisible to the public internet).
- **Watcher registry + event fan-out (reverse-push architecture)**:
  - `instrumentation.ts` boots a singleton NATS subscriber on `triage.events.v1.>`, `triage.cancel.v1.>`, `auth.revocations.v1.>`.
  - For each event, looks up DO watchers in Redis and POSTs to the gateway `/push` endpoint, which routes to the right DO instance.
  - `/api/internal/{watch,unwatch,disconnect,cancel}` — gateway-only routes the DO calls to register/deregister. Auth via the `gateway` service JWT.

What it does NOT do:
- Parse alerts. That's authoritative on FastAPI.
- Run triage. That's the worker.
- Hold WebSockets. That's the Cloudflare DO (`gateway/`).

## Local dev

```bash
cd frontend
cp .env.example .env.local
npm install         # not yet done in this scaffold
npm run dev
```

Required services (run from repo root):
- NATS on `:4222`
- Redis on `:6379`
- Postgres on `:5432` (with the `service_secrets` table created — Postgres init runs automatically when the FastAPI worker boots; you can also seed manually with `uv run python -m services._runtime.secret_publisher rotate`)
- FastAPI on `:8000` (`make api` from the repo root)

## Layout

```
frontend/
  instrumentation.ts            Next.js boot hook → starts the fan-out
  app/
    api/
      auth/{login,refresh,logout}/route.ts
      ws/{ticket,redeem}/route.ts
      ingest/route.ts
      alerts/[alert_id]/snapshot/route.ts   proxy to FastAPI
      internal/{watch,unwatch,disconnect,cancel}/route.ts   DO ↔ BFF
    layout.tsx
    page.tsx                    placeholder UI
  lib/
    db.ts                       Postgres pool (pg)
    redis.ts                    Redis client (ioredis)
    secrets.ts                  reads service_secrets rows from Postgres
    jwt.ts                      sign/verify external + internal HS256 (jose)
    session.ts                  CRUD on session:{user_id}, ws ticket store
    users.ts                    CRUD on users table
    password.ts                 argon2id wrapper
    cookies.ts                  HttpOnly+Secure refresh cookie helpers
    auth-guard.ts               access-token bearer check for /api/*
    gateway-guard.ts            gateway service-token check for /api/internal/*
    nats.ts                     revocation publisher
    event-fanout.ts             NATS subscriber → POSTs to DO push_url
    watcher-registry.ts         Redis CRUD for DO watcher entries
    config.ts                   env-loaded constants
```

## Auth invariants (do not weaken)

1. `tenant_id` always comes from the verified access token, never from the request body.
2. The refresh-token cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, scoped to the BFF's domain.
3. Refresh tokens rotate on every use. Reuse of an already-consumed `refresh_jti` is treated as theft and burns the entire session family.
4. The internal service-token signing keys (`ingest`/`worker`/`gateway`) are read from `service_secrets` in Postgres — they are never embedded in environment variables in production.
5. The browser never receives a token whose audience is `worker` or `ingest`.
