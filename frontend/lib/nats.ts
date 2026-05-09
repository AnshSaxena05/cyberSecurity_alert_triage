// NATS publisher used by the BFF for two purposes:
//
//   1) auth.revocations.v1.{tenant}.{user}  — fired on logout. Every DO
//      subscribed to its tenant's revocation prefix force-closes any
//      matching open WebSocket within ~1 second.
//
//   2) (future) auth.revocations.v1.{tenant}.{user}.role-change — when
//      a user's role/tenant changes mid-session and we want their open
//      WS to drop without waiting for the access-token TTL.
//
// Single shared NATS connection; lazy-initialised; degrades gracefully if
// NATS is unreachable (logout still completes; we just log a warning).

import "server-only";

import { connect, type NatsConnection, StringCodec } from "nats";

import { Config } from "./config";

let _nc: NatsConnection | null = null;
let _connecting: Promise<NatsConnection | null> | null = null;
const sc = StringCodec();

async function getConn(): Promise<NatsConnection | null> {
  if (_nc && !(_nc as unknown as { isClosed?: () => boolean }).isClosed?.()) {
    return _nc;
  }
  if (_connecting) return _connecting;
  _connecting = (async () => {
    try {
      _nc = await connect({
        servers: Config.natsUrl,
        name: "soc-triage-bff",
        reconnect: true,
        maxReconnectAttempts: -1,
        waitOnFirstConnect: false,
      });
      return _nc;
    } catch (err) {
      console.error("[nats] connect failed:", (err as Error).message);
      return null;
    } finally {
      _connecting = null;
    }
  })();
  return _connecting;
}

export async function publishRevocation(args: {
  tenantId: string;
  userId: string;
  reason?: "logout" | "lockout" | "role_change";
}): Promise<boolean> {
  const subject = `${Config.revocationSubjectPrefix}.${args.tenantId}.${args.userId}`;
  const body = sc.encode(
    JSON.stringify({
      tenant_id: args.tenantId,
      user_id: args.userId,
      reason: args.reason ?? "logout",
      at: new Date().toISOString(),
    }),
  );
  const nc = await getConn();
  if (!nc) {
    return false;
  }
  try {
    nc.publish(subject, body);
    await nc.flush();
    return true;
  } catch (err) {
    console.error("[nats] publish failed:", (err as Error).message);
    return false;
  }
}

export async function closeNats(): Promise<void> {
  if (_nc) {
    try {
      await _nc.drain();
    } catch {
      /* ignore */
    }
    _nc = null;
  }
}
