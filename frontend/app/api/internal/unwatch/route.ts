// POST /api/internal/unwatch
// Called by the DO on `{type: "unwatch", alert_id}` from the browser.
// Removes one (do_id, alert_id) pair from the watcher registry.

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";

import { requireGatewayToken } from "@/lib/gateway-guard";
import { deregisterWatch } from "@/lib/watcher-registry";

export const runtime = "nodejs";

const UnwatchBody = z.object({
  do_id: z.string().min(1).max(128),
  alert_id: z.string().min(1).max(256),
});

export async function POST(req: NextRequest): Promise<NextResponse> {
  const claims = await requireGatewayToken(req);
  if (claims instanceof NextResponse) return claims;

  let body: z.infer<typeof UnwatchBody>;
  try {
    body = UnwatchBody.parse(await req.json());
  } catch (err) {
    return NextResponse.json(
      { error: "invalid_request", detail: (err as Error).message },
      { status: 400 },
    );
  }

  await deregisterWatch({
    doId: body.do_id,
    alertId: body.alert_id,
    tenantId: claims.tid,
  });
  return NextResponse.json({ ok: true });
}
