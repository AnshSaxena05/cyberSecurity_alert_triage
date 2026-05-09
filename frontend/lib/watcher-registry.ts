// DO watcher registry, Redis-backed.
//
// Layout:
//   watcher_meta:{do_id}              hash → { user_id, tenant_id, push_url, last_seen }
//   alert_watchers:{tenant}:{alert_id}  set  → set of do_ids watching this alert
//   user_dos:{tenant}:{user_id}       set  → set of do_ids belonging to this user
//   do_alerts:{do_id}                 set  → set of alert_ids this DO is watching
//
// All keys carry a TTL (default 10 minutes); every successful event push
// refreshes the TTL on the relevant entries so a healthy DO never expires
// while events are flowing. Idle DOs roll off naturally — no manual GC.
//
// Tenant prefixing on the alert/user indices is defense-in-depth: even if
// a code path forgets to scope a query by tenant, the key namespace keeps
// tenants separated.

import "server-only";

import { redis } from "./redis";

const DEFAULT_TTL_SEC = 10 * 60;

const k = {
  meta: (doId: string) => `watcher_meta:${doId}`,
  alert: (tenantId: string, alertId: string) => `alert_watchers:${tenantId}:${alertId}`,
  user: (tenantId: string, userId: string) => `user_dos:${tenantId}:${userId}`,
  doAlerts: (doId: string) => `do_alerts:${doId}`,
};

export interface WatcherMeta {
  do_id: string;
  user_id: string;
  tenant_id: string;
  push_url: string;
  last_seen_epoch: number;
}

// ---------------------------------------------------------------------------
// Register / deregister
// ---------------------------------------------------------------------------

export async function registerWatch(args: {
  doId: string;
  userId: string;
  tenantId: string;
  alertId: string;
  pushUrl: string;
  ttlSeconds?: number;
}): Promise<void> {
  const ttl = args.ttlSeconds ?? DEFAULT_TTL_SEC;
  const r = redis();
  const now = Math.floor(Date.now() / 1000);

  // Pipeline so all four updates land in one round-trip.
  const pipe = r.multi();
  pipe.hset(k.meta(args.doId), {
    user_id: args.userId,
    tenant_id: args.tenantId,
    push_url: args.pushUrl,
    last_seen_epoch: String(now),
  });
  pipe.expire(k.meta(args.doId), ttl);
  pipe.sadd(k.alert(args.tenantId, args.alertId), args.doId);
  pipe.expire(k.alert(args.tenantId, args.alertId), ttl);
  pipe.sadd(k.user(args.tenantId, args.userId), args.doId);
  pipe.expire(k.user(args.tenantId, args.userId), ttl);
  pipe.sadd(k.doAlerts(args.doId), args.alertId);
  pipe.expire(k.doAlerts(args.doId), ttl);
  await pipe.exec();
}

export async function deregisterWatch(args: {
  doId: string;
  alertId: string;
  tenantId?: string;        // optional optimisation; falls back to meta lookup
}): Promise<void> {
  const r = redis();
  const tenantId = args.tenantId ?? (await getMeta(args.doId))?.tenant_id;
  const pipe = r.multi();
  if (tenantId) {
    pipe.srem(k.alert(tenantId, args.alertId), args.doId);
  }
  pipe.srem(k.doAlerts(args.doId), args.alertId);
  await pipe.exec();
}

export async function deregisterDo(doId: string): Promise<void> {
  const meta = await getMeta(doId);
  if (!meta) return;
  const r = redis();
  const alertIds = await r.smembers(k.doAlerts(doId));
  const pipe = r.multi();
  for (const alertId of alertIds) {
    pipe.srem(k.alert(meta.tenant_id, alertId), doId);
  }
  pipe.srem(k.user(meta.tenant_id, meta.user_id), doId);
  pipe.del(k.meta(doId));
  pipe.del(k.doAlerts(doId));
  await pipe.exec();
}

// ---------------------------------------------------------------------------
// Lookups (used by the fan-out)
// ---------------------------------------------------------------------------

export async function watchersForAlert(
  tenantId: string,
  alertId: string,
): Promise<WatcherMeta[]> {
  const r = redis();
  const doIds = await r.smembers(k.alert(tenantId, alertId));
  if (doIds.length === 0) return [];
  const metas = await Promise.all(doIds.map((id) => getMeta(id)));
  return metas.filter((m): m is WatcherMeta => m !== null);
}

export async function dosForUser(
  tenantId: string,
  userId: string,
): Promise<WatcherMeta[]> {
  const r = redis();
  const doIds = await r.smembers(k.user(tenantId, userId));
  if (doIds.length === 0) return [];
  const metas = await Promise.all(doIds.map((id) => getMeta(id)));
  return metas.filter((m): m is WatcherMeta => m !== null);
}

export async function getMeta(doId: string): Promise<WatcherMeta | null> {
  const r = redis();
  const h = await r.hgetall(k.meta(doId));
  if (!h || Object.keys(h).length === 0) return null;
  return {
    do_id: doId,
    user_id: h.user_id ?? "",
    tenant_id: h.tenant_id ?? "",
    push_url: h.push_url ?? "",
    last_seen_epoch: parseInt(h.last_seen_epoch ?? "0", 10),
  };
}

export async function refreshTtl(
  doId: string,
  alertId: string,
  tenantId: string,
  ttlSeconds = DEFAULT_TTL_SEC,
): Promise<void> {
  const r = redis();
  const pipe = r.multi();
  pipe.expire(k.meta(doId), ttlSeconds);
  pipe.expire(k.alert(tenantId, alertId), ttlSeconds);
  pipe.expire(k.doAlerts(doId), ttlSeconds);
  // Bump last_seen so we can identify zombie entries later.
  pipe.hset(k.meta(doId), {
    last_seen_epoch: String(Math.floor(Date.now() / 1000)),
  });
  await pipe.exec();
}

// ---------------------------------------------------------------------------
// Pruning — called by the fan-out when a DO's /push returns 410 (gone)
// or 404 (DO id unknown). Removes the DO from every index it touches.
// ---------------------------------------------------------------------------

export async function pruneDoEverywhere(doId: string): Promise<void> {
  await deregisterDo(doId);
}
