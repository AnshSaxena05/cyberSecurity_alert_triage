// POST /api/internal/cancel
// Called by the DO after the 5s grace window expires on WS close.
// We translate this into a NATS publish on triage.cancel.v1.{tenant}.{alert}
// so the Python worker's cancel-listener picks it up and short-circuits
// the in-flight LangGraph at the next LLM-call boundary.

import { NextRequest, NextResponse } from "next/server";
import { connect, StringCodec, type NatsConnection } from "nats";
import { z } from "zod";

import { Config } from "@/lib/config";
import { requireGatewayToken } from "@/lib/gateway-guard";

export const runtime = "nodejs";

const CancelBody = z.object({
  do_id: z.string().min(1).max(128),
  tenant_id: z.string().min(1).max(128),
  user_id: z.string().min(1).max(128),
  alert_id: z.string().min(1).max(256),
});

let _nc: NatsConnection | null = null;
const sc = StringCodec();

async function getNc(): Promise<NatsConnection | null> {
  if (_nc) return _nc;
  try {
    _nc = await connect({
      servers: Config.natsUrl,
      name: "soc-bff-cancel-publisher",
      reconnect: true,
      maxReconnectAttempts: -1,
    });
    return _nc;
  } catch (err) {
    console.error("[cancel] nats connect failed:", (err as Error).message);
    return null;
  }
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const claims = await requireGatewayToken(req);
  if (claims instanceof NextResponse) return claims;

  let body: z.infer<typeof CancelBody>;
  try {
    body = CancelBody.parse(await req.json());
  } catch (err) {
    return NextResponse.json(
      { error: "invalid_request", detail: (err as Error).message },
      { status: 400 },
    );
  }
  // tenant_id authoritative from JWT.
  if (claims.tid !== body.tenant_id) {
    return NextResponse.json({ error: "tenant_mismatch" }, { status: 403 });
  }

  const nc = await getNc();
  if (!nc) {
    return NextResponse.json({ error: "broker_unavailable" }, { status: 503 });
  }
  const subject = `triage.cancel.v1.${claims.tid}.${body.alert_id}`;
  const payload = sc.encode(
    JSON.stringify({
      alert_id: body.alert_id,
      tenant_id: claims.tid,
      user_id: body.user_id,
      reason: "ws_closed",
      requested_at: new Date().toISOString(),
    }),
  );
  try {
    nc.publish(subject, payload);
    await nc.flush();
  } catch (err) {
    console.error("[cancel] publish failed:", (err as Error).message);
    return NextResponse.json({ error: "publish_failed" }, { status: 502 });
  }
  return NextResponse.json({ ok: true });
}
