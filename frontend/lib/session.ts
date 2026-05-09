// Session store. Refresh-token-rotation pattern.
//
// Layout (Redis):
//   session:{user_id}                 → JSON {refresh_jti, family_id, ip, ua, role, tenant_id, last_seen_epoch}
//   refresh:{family_id}:{refresh_jti} → "1", EX = refresh TTL — used to detect refresh-token reuse
//   revoked_jti:{access_jti}          → "1", EX = 900 — instant access-token kill list
//
// The "family_id" is shared across rotations of a single login session.
// If a `refresh:{family}:{old_jti}` key is asked for and it has already
// been consumed (deleted at the rotation step), we treat the WHOLE family
// as compromised and burn it. That's the canonical refresh-token-theft
// mitigation.

import "server-only";

import { randomBytes } from "node:crypto";

import { Config } from "./config";
import { redis } from "./redis";

export interface SessionRecord {
  user_id: string;
  tenant_id: string;
  role: string | null;
  family_id: string;
  refresh_jti: string;
  ip?: string;
  ua?: string;
  last_seen_epoch: number;
}

export const sessionKey = (userId: string) => `session:${userId}`;
export const refreshKey = (family: string, jti: string) => `refresh:${family}:${jti}`;
export const familyIndexKey = (family: string) => `family_index:${family}`;
export const revokedJtiKey = (jti: string) => `revoked_jti:${jti}`;
export const wsTicketKey = (ticket: string) => `wsticket:${ticket}`;

function newId(): string {
  return randomBytes(16).toString("base64url");
}

// ---------------------------------------------------------------------------
// Login → fresh session
// ---------------------------------------------------------------------------

export async function startSession(args: {
  userId: string;
  tenantId: string;
  role: string | null;
  ip?: string;
  ua?: string;
}): Promise<{ refreshToken: string; familyId: string }> {
  const familyId = newId();
  const refreshJti = newId();
  const refreshToken = `${familyId}.${refreshJti}`;
  const now = Math.floor(Date.now() / 1000);
  const record: SessionRecord = {
    user_id: args.userId,
    tenant_id: args.tenantId,
    role: args.role,
    family_id: familyId,
    refresh_jti: refreshJti,
    ip: args.ip,
    ua: args.ua,
    last_seen_epoch: now,
  };
  const r = redis();
  await r.set(sessionKey(args.userId), JSON.stringify(record));
  await r.set(
    familyIndexKey(familyId),
    args.userId,
    "EX",
    Config.refreshTokenTtlSeconds,
  );
  await r.set(
    refreshKey(familyId, refreshJti),
    "1",
    "EX",
    Config.refreshTokenTtlSeconds,
  );
  return { refreshToken, familyId };
}

// ---------------------------------------------------------------------------
// Refresh: validate the old refresh token, rotate to a new one
// ---------------------------------------------------------------------------

export interface RefreshOutcome {
  ok: true;
  session: SessionRecord;
  newRefreshToken: string;
}

export interface RefreshFailure {
  ok: false;
  reason: "missing" | "reused" | "expired" | "user_unknown";
}

export async function rotateRefresh(args: {
  refreshToken: string;
}): Promise<RefreshOutcome | RefreshFailure> {
  const [familyId, oldJti] = args.refreshToken.split(".");
  if (!familyId || !oldJti) {
    return { ok: false, reason: "missing" };
  }

  const r = redis();
  // Atomically consume the old jti. If DEL returns 0 the token was already
  // used or never existed → treat as reuse.
  const consumed = await r.del(refreshKey(familyId, oldJti));
  if (consumed === 0) {
    // Reuse-detection: scrub the entire family.
    await burnFamily(familyId);
    return { ok: false, reason: "reused" };
  }

  // Find the session that owns this family. We index by user_id, so we
  // need a reverse lookup; cheap path: keep the family_id on the session
  // record and reject the rotation if it doesn't match. We use the
  // refresh token as the source of truth for which session to load.
  const sessionUserId = await findUserIdByFamily(familyId);
  if (!sessionUserId) {
    return { ok: false, reason: "user_unknown" };
  }
  const sessionJson = await r.get(sessionKey(sessionUserId));
  if (!sessionJson) {
    return { ok: false, reason: "expired" };
  }
  const session = JSON.parse(sessionJson) as SessionRecord;
  if (session.family_id !== familyId || session.refresh_jti !== oldJti) {
    // Token + session mismatch — could be an in-flight race or theft.
    await burnFamily(familyId);
    return { ok: false, reason: "reused" };
  }

  // Mint the new jti.
  const newJti = newId();
  const newToken = `${familyId}.${newJti}`;
  session.refresh_jti = newJti;
  session.last_seen_epoch = Math.floor(Date.now() / 1000);
  await r.set(sessionKey(sessionUserId), JSON.stringify(session));
  await r.set(
    refreshKey(familyId, newJti),
    "1",
    "EX",
    Config.refreshTokenTtlSeconds,
  );
  return { ok: true, session, newRefreshToken: newToken };
}

// ---------------------------------------------------------------------------
// Logout / revocation
// ---------------------------------------------------------------------------

export async function endSession(userId: string): Promise<SessionRecord | null> {
  const r = redis();
  const json = await r.get(sessionKey(userId));
  if (!json) return null;
  const session = JSON.parse(json) as SessionRecord;
  await Promise.all([
    r.del(sessionKey(userId)),
    burnFamily(session.family_id),
  ]);
  return session;
}

export async function denyJti(jti: string, ttlSeconds = 900): Promise<void> {
  await redis().set(revokedJtiKey(jti), "1", "EX", ttlSeconds);
}

export async function isJtiDenied(jti: string): Promise<boolean> {
  const v = await redis().get(revokedJtiKey(jti));
  return v === "1";
}

// ---------------------------------------------------------------------------
// WS ticket — single-use, 60s
// ---------------------------------------------------------------------------

export async function issueWsTicket(args: {
  userId: string;
  tenantId: string;
  role: string | null;
}): Promise<string> {
  const ticket = newId();
  const r = redis();
  const payload = JSON.stringify({
    user_id: args.userId,
    tenant_id: args.tenantId,
    role: args.role,
  });
  await r.set(wsTicketKey(ticket), payload, "EX", Config.wsTicketTtlSeconds);
  return ticket;
}

export async function consumeWsTicket(
  ticket: string,
): Promise<{ user_id: string; tenant_id: string; role: string | null } | null> {
  const r = redis();
  // GETDEL is atomic — reads and removes in one round trip.
  const raw = await r.getdel(wsTicketKey(ticket));
  if (!raw) return null;
  return JSON.parse(raw);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function burnFamily(familyId: string): Promise<void> {
  const r = redis();
  // Drop the index immediately so future rotations / probes can't find it.
  await r.del(familyIndexKey(familyId));
  // SCAN by family prefix and delete every refresh jti under it.
  const stream = r.scanStream({ match: refreshKey(familyId, "*"), count: 100 });
  for await (const keys of stream) {
    if (keys.length === 0) continue;
    await r.del(...keys);
  }
}

async function findUserIdByFamily(familyId: string): Promise<string | null> {
  return await redis().get(familyIndexKey(familyId));
}
