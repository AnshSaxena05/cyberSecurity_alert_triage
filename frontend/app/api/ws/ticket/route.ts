// POST /api/ws/ticket
// Issues a single-use 60s ticket for the browser to exchange with the
// Cloudflare Durable Object on WebSocket connect. The ticket is the
// only "secret" that ever appears in the WS query string — short-lived
// enough that proxy logs cannot replay it.
//
// Request:  authenticated with the access JWT (Authorization: Bearer)
// Response: 200 { ticket, expires_in_seconds }

import { NextRequest, NextResponse } from "next/server";

import { requireAccessToken } from "@/lib/auth-guard";
import { Config } from "@/lib/config";
import { issueWsTicket } from "@/lib/session";

export const runtime = "nodejs";

export async function POST(req: NextRequest): Promise<NextResponse> {
  const claims = await requireAccessToken(req);
  if (claims instanceof NextResponse) return claims;

  const ticket = await issueWsTicket({
    userId: claims.sub,
    tenantId: claims.tid,
    role: claims.role,
  });
  return NextResponse.json({
    ticket,
    expires_in_seconds: Config.wsTicketTtlSeconds,
  });
}
