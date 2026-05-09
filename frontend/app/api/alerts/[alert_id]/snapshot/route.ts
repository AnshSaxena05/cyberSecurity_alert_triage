// GET /api/alerts/{alert_id}/snapshot
// BFF proxy in front of FastAPI's /api/alerts/{id}/snapshot. The DO
// never talks to FastAPI directly — it always goes through the BFF so
// the Python backend stays invisible to the public internet.
//
// Auth: gateway service JWT. The BFF mints an `ingest`-audience service
// JWT and forwards.

import { NextRequest, NextResponse } from "next/server";

import { Config } from "@/lib/config";
import { requireGatewayToken } from "@/lib/gateway-guard";
import { mintServiceToken } from "@/lib/jwt";

export const runtime = "nodejs";

export async function GET(
  req: NextRequest,
  { params }: { params: { alert_id: string } },
): Promise<NextResponse> {
  const claims = await requireGatewayToken(req);
  if (claims instanceof NextResponse) return claims;

  const alertId = params.alert_id;
  if (!alertId || alertId.length > 256) {
    return NextResponse.json({ error: "invalid_alert_id" }, { status: 400 });
  }

  const ingestToken = await mintServiceToken({
    targetAudience: Config.audiences.ingest,
    userId: claims.sub,
    tenantId: claims.tid,
  });
  const url = new URL(`/api/alerts/${alertId}/snapshot`, Config.socApiBaseUrl);
  let resp: Response;
  try {
    resp = await fetch(url, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${ingestToken}`,
      },
    });
  } catch (err) {
    return NextResponse.json(
      { error: "upstream_unreachable", detail: (err as Error).message },
      { status: 502 },
    );
  }
  const text = await resp.text();
  return new NextResponse(text || null, {
    status: resp.status,
    headers: {
      "Content-Type": resp.headers.get("content-type") ?? "application/json",
    },
  });
}
