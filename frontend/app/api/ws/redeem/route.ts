// POST /api/ws/redeem
// Called server-to-server by the Cloudflare Durable Object during the
// WebSocket upgrade handshake. The DO POSTs the ticket value here; we
// atomically consume it (GETDEL) and return the user_id + tenant_id +
// role so the DO can attach them to the per-WS state.
//
// Authentication: a shared mTLS / IP allowlist between BFF and gateway is
// the production-grade story. For now we accept a `gateway` service JWT
// (audience=gateway) so we can ship without infra plumbing — this still
// keeps tickets unreplayable from the public internet.

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";

import { Config } from "@/lib/config";
import { verifyServiceToken } from "@/lib/jwt";
import { consumeWsTicket } from "@/lib/session";

export const runtime = "nodejs";

const RedeemBody = z.object({
  ticket: z.string().min(8).max(256),
});

export async function POST(req: NextRequest): Promise<NextResponse> {
  // The gateway must present a service JWT addressed to the gateway audience.
  // The BFF (issuer) and gateway share the secret via Postgres; the gateway
  // mints with its own bundle, the BFF verifies.
  const auth = req.headers.get("authorization") ?? "";
  const token = auth.toLowerCase().startsWith("bearer ")
    ? auth.slice("bearer ".length).trim()
    : "";
  if (!token) {
    return NextResponse.json({ error: "missing_service_token" }, { status: 401 });
  }
  try {
    await verifyServiceToken(token, Config.audiences.gateway);
  } catch {
    return NextResponse.json({ error: "invalid_service_token" }, { status: 401 });
  }

  let body: z.infer<typeof RedeemBody>;
  try {
    body = RedeemBody.parse(await req.json());
  } catch (err) {
    return NextResponse.json(
      { error: "invalid_request", detail: (err as Error).message },
      { status: 400 },
    );
  }

  const session = await consumeWsTicket(body.ticket);
  if (!session) {
    // Already consumed, expired, or never existed. We deliberately do not
    // distinguish — failure mode is identical for the gateway.
    return NextResponse.json({ error: "invalid_or_consumed_ticket" }, { status: 401 });
  }
  return NextResponse.json(session);
}
