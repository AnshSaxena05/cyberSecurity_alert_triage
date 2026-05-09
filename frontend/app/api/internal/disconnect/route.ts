// POST /api/internal/disconnect
// Called by the DO on WebSocket close. Drops every registry entry
// belonging to this DO so the fan-out stops trying to push to a dead
// instance. Eviction by Cloudflare is idempotent here — the DO might
// already be gone and the next push would 410 anyway, but the explicit
// signal is cheaper than letting entries linger until TTL.

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";

import { requireGatewayToken } from "@/lib/gateway-guard";
import { deregisterDo } from "@/lib/watcher-registry";

export const runtime = "nodejs";

const DisconnectBody = z.object({
  do_id: z.string().min(1).max(128),
  user_id: z.string().min(1).max(128),
});

export async function POST(req: NextRequest): Promise<NextResponse> {
  const claims = await requireGatewayToken(req);
  if (claims instanceof NextResponse) return claims;

  let body: z.infer<typeof DisconnectBody>;
  try {
    body = DisconnectBody.parse(await req.json());
  } catch (err) {
    return NextResponse.json(
      { error: "invalid_request", detail: (err as Error).message },
      { status: 400 },
    );
  }

  // tenant_id comes from auth, not body — DO never leaks it through here.
  void claims.tid;
  await deregisterDo(body.do_id);
  return NextResponse.json({ ok: true });
}
