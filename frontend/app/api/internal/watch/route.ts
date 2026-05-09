// POST /api/internal/watch
// Called by the Cloudflare DO when the browser sends `{type: "watch", alert_id}`.
// Persists the registration so the fan-out service knows where to push
// future triage events for that alert.
//
// Auth: gateway service JWT. Body shape: WatchRegistration (see
// gateway/src/types.ts).

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";

import { requireGatewayToken } from "@/lib/gateway-guard";
import { registerWatch } from "@/lib/watcher-registry";

export const runtime = "nodejs";

const WatchBody = z.object({
  do_id: z.string().min(1).max(128),
  user_id: z.string().min(1).max(128),
  tenant_id: z.string().min(1).max(128),
  alert_id: z.string().min(1).max(256),
  push_url: z.string().url().max(512),
});

export async function POST(req: NextRequest): Promise<NextResponse> {
  const claims = await requireGatewayToken(req);
  if (claims instanceof NextResponse) return claims;

  let body: z.infer<typeof WatchBody>;
  try {
    body = WatchBody.parse(await req.json());
  } catch (err) {
    return NextResponse.json(
      { error: "invalid_request", detail: (err as Error).message },
      { status: 400 },
    );
  }

  // Tenant-id from the verified JWT wins over anything in the body —
  // even though both must match, this enforces the "auth context owns
  // tenant" rule from the architecture plan §A7.
  if (claims.tid !== body.tenant_id) {
    return NextResponse.json(
      { error: "tenant_mismatch", detail: "JWT tid does not match body.tenant_id" },
      { status: 403 },
    );
  }

  await registerWatch({
    doId: body.do_id,
    userId: body.user_id,
    tenantId: claims.tid,
    alertId: body.alert_id,
    pushUrl: body.push_url,
  });
  return NextResponse.json({ ok: true });
}
