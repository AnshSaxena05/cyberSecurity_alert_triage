// Event fan-out service.
//
// Long-lived NATS subscriber that runs as a singleton on the Next.js
// server process. For every triage event / cancel / revocation it:
//
//   1. Looks up DO watchers from Redis (alert_watchers, user_dos).
//   2. POSTs the event payload to each DO's push_url with header
//      ``Authorization: Bearer <gateway service JWT>``.
//   3. On 410 (no active WS) or 404 (DO unknown), prunes the DO entry.
//   4. On 5xx / network failure, retries with bounded back-off; gives up
//      after the per-event budget so a single bad DO can't stall the
//      whole stream.
//
// The fan-out subscribes with a *queue group* so multiple BFF instances
// load-balance NATS messages: each event is delivered exactly once to the
// fleet. Adding a second BFF process is a horizontal scale; no leader
// election needed.

import "server-only";

import { connect, headers, type NatsConnection, StringCodec } from "nats";

import { Config } from "./config";
import { mintServiceToken } from "./jwt";
import {
  dosForUser,
  pruneDoEverywhere,
  refreshTtl,
  watchersForAlert,
  type WatcherMeta,
} from "./watcher-registry";

const QUEUE_GROUP = "soc-bff-fanout";

interface NatsTriageEvent {
  alert_id?: string;
  tenant_id?: string;
  user_id?: string;
  // anything else is forwarded verbatim
  [key: string]: unknown;
}

let started = false;
let nc: NatsConnection | null = null;
const sc = StringCodec();

export async function startEventFanout(): Promise<void> {
  if (started) return;
  started = true;
  try {
    nc = await connect({
      servers: Config.natsUrl,
      name: "soc-bff-fanout",
      reconnect: true,
      maxReconnectAttempts: -1,
    });
    console.log("[fanout] connected to", Config.natsUrl);

    void subscribeForever(nc, "triage.events.v1.>", (subject, payload) =>
      onTriageEvent(subject, payload, "phase_or_token"),
    );
    void subscribeForever(nc, "triage.cancel.v1.>", (subject, payload) =>
      onTriageEvent(subject, payload, "cancel"),
    );
    void subscribeForever(nc, "auth.revocations.v1.>", (subject, payload) =>
      onRevocationEvent(subject, payload),
    );
  } catch (err) {
    console.error("[fanout] connect failed:", (err as Error).message);
    started = false;   // allow a retry on next boot hook
  }
}

export async function stopEventFanout(): Promise<void> {
  if (nc) {
    try {
      await nc.drain();
    } catch {
      /* ignore */
    }
    nc = null;
  }
  started = false;
}

// ---------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------

async function subscribeForever(
  conn: NatsConnection,
  subject: string,
  handler: (subject: string, body: NatsTriageEvent) => Promise<void>,
): Promise<void> {
  const sub = conn.subscribe(subject, { queue: QUEUE_GROUP });
  for await (const m of sub) {
    let body: NatsTriageEvent;
    try {
      body = JSON.parse(sc.decode(m.data)) as NatsTriageEvent;
    } catch (err) {
      console.warn("[fanout] non-json message on", m.subject, (err as Error).message);
      continue;
    }
    try {
      await handler(m.subject, body);
    } catch (err) {
      console.error("[fanout] handler error on", m.subject, (err as Error).message);
    }
  }
}

async function onTriageEvent(
  subject: string,
  body: NatsTriageEvent,
  shape: "phase_or_token" | "cancel",
): Promise<void> {
  const { tenant_id, alert_id } = extractTenantAlertFromSubject(subject) ?? {};
  const tenantId = (body.tenant_id as string | undefined) ?? tenant_id;
  const alertId = (body.alert_id as string | undefined) ?? alert_id;
  if (!tenantId || !alertId) {
    console.warn("[fanout] dropping event with missing tenant/alert", subject);
    return;
  }

  const watchers = await watchersForAlert(tenantId, alertId);
  if (watchers.length === 0) return;

  const envelope = shape === "cancel"
    ? { kind: "cancel", cancel: { alert_id: alertId } }
    : { kind: inferKindFromBody(body), event: body };

  await Promise.all(
    watchers.map((w) => pushWithRetry(w, envelope, tenantId, alertId)),
  );
}

async function onRevocationEvent(
  subject: string,
  body: NatsTriageEvent,
): Promise<void> {
  // Subject: auth.revocations.v1.{tenant_id}.{user_id}
  const parts = subject.split(".");
  const tenantId = (body.tenant_id as string | undefined) ?? parts[3];
  const userId = (body.user_id as string | undefined) ?? parts[4];
  if (!tenantId || !userId) {
    console.warn("[fanout] revocation missing tenant/user", subject);
    return;
  }
  const dos = await dosForUser(tenantId, userId);
  if (dos.length === 0) return;

  const envelope = { kind: "revoked", revoked: { user_id: userId } };
  await Promise.all(dos.map((w) => pushWithRetry(w, envelope, tenantId, null)));
}

// ---------------------------------------------------------------------------
// Push with retry + prune-on-gone
// ---------------------------------------------------------------------------

async function pushWithRetry(
  watcher: WatcherMeta,
  envelope: unknown,
  tenantId: string,
  alertId: string | null,
): Promise<void> {
  const token = await mintServiceToken({
    targetAudience: Config.audiences.gateway,
    userId: watcher.user_id,
    tenantId,
  });
  const url = `${watcher.push_url}?do=${encodeURIComponent(watcher.do_id)}`;

  let attempt = 0;
  const maxAttempts = 3;
  while (attempt < maxAttempts) {
    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
          ...(unwrap(envelope, "kind") === "phase" || unwrap(envelope, "kind") === "token"
            ? naFetchHeaders()
            : {}),
        },
        body: JSON.stringify(envelope),
      });
      if (resp.status === 204) {
        if (alertId) {
          // Successful delivery refreshes the TTL on this watcher's keys
          // so an actively-streamed alert doesn't expire from the registry.
          await refreshTtl(watcher.do_id, alertId, tenantId);
        }
        return;
      }
      if (resp.status === 410 || resp.status === 404) {
        // DO is gone or evicted with no live WS. Drop the entry so we
        // don't waste future requests on it.
        await pruneDoEverywhere(watcher.do_id);
        return;
      }
      // 4xx other than 410/404 are non-retryable — bad request / auth
      // problems. Drop the entry to be safe.
      if (resp.status >= 400 && resp.status < 500) {
        console.warn(
          "[fanout] non-retryable from gateway",
          resp.status,
          watcher.do_id,
        );
        return;
      }
      // 5xx — retry with backoff.
    } catch (err) {
      console.warn(
        "[fanout] push error",
        watcher.do_id,
        (err as Error).message,
        `attempt ${attempt + 1}`,
      );
    }
    attempt += 1;
    if (attempt < maxAttempts) {
      await new Promise((r) => setTimeout(r, 100 * attempt));
    }
  }
}

// ---------------------------------------------------------------------------
// Tiny helpers
// ---------------------------------------------------------------------------

function extractTenantAlertFromSubject(
  subject: string,
): { tenant_id: string; alert_id: string } | null {
  // triage.events.v1.{tenant}.{alert}.{phase}
  // triage.cancel.v1.{tenant}.{alert}
  const parts = subject.split(".");
  if (parts.length < 5) return null;
  if (parts[0] === "triage" && parts[1] === "events" && parts[2] === "v1") {
    return { tenant_id: parts[3], alert_id: parts[4] };
  }
  if (parts[0] === "triage" && parts[1] === "cancel" && parts[2] === "v1") {
    return { tenant_id: parts[3], alert_id: parts[4] };
  }
  return null;
}

function inferKindFromBody(body: NatsTriageEvent): "phase" | "token" {
  return body.kind === "token" ? "token" : "phase";
}

function unwrap(obj: unknown, key: string): unknown {
  return obj && typeof obj === "object" ? (obj as Record<string, unknown>)[key] : undefined;
}

function naFetchHeaders(): Record<string, string> {
  // Placeholder for any future per-shape headers (e.g. trace context).
  // Kept as a function so we don't sprinkle inline objects that drift.
  void headers;   // keep nats import shaped if we add traceparent later
  return {};
}
