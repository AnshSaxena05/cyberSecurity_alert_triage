// POST /api/ingest
// Body: { source: AlertSource, payload: object } | raw payload (auto-detect)
//
// The browser uploads alert JSON here. The BFF:
//   1. Verifies the access token.
//   2. Mints a service JWT addressed to ``ingest`` audience.
//   3. Forwards the request to FastAPI's /ingest/{source} or /ingest/auto.
//   4. Returns FastAPI's 202 response (alert_id) verbatim.
//
// The browser never sees the service token. tenant_id is taken from the
// access-token claims; any tenant_id in the body is ignored — that's the
// architectural rule from plan §A7.

import { randomBytes } from "node:crypto";

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";

import { requireAccessToken } from "@/lib/auth-guard";
import { Config } from "@/lib/config";
import { mintServiceToken } from "@/lib/jwt";

export const runtime = "nodejs";

const IngestBody = z.union([
  z.object({
    source: z.enum(["splunk", "crowdstrike", "aws_guardduty", "sentinel", "generic"]),
    payload: z.record(z.unknown()),
  }),
  z.object({
    payload: z.record(z.unknown()),
  }),
]);

export async function POST(req: NextRequest): Promise<NextResponse> {
  const claims = await requireAccessToken(req);
  if (claims instanceof NextResponse) return claims;

  let body: z.infer<typeof IngestBody>;
  try {
    body = IngestBody.parse(await req.json());
  } catch (err) {
    return NextResponse.json(
      { error: "invalid_request", detail: (err as Error).message },
      { status: 400 },
    );
  }

  const source = "source" in body ? body.source : null;
  const path = source ? `/ingest/${source}` : "/ingest/auto";

  const reqId = randomBytes(8).toString("base64url");
  const serviceToken = await mintServiceToken({
    targetAudience: Config.audiences.ingest,
    userId: claims.sub,
    tenantId: claims.tid,
    role: claims.role,
    reqId,
  });

  // Strip any client-supplied tenant_id BEFORE forwarding. FastAPI will
  // also re-derive from the JWT, but defense-in-depth is cheap.
  const cleanedPayload = { ...body.payload };
  delete (cleanedPayload as Record<string, unknown>).tenant_id;

  const url = new URL(path, Config.socApiBaseUrl).toString();
  let resp: Response;
  try {
    resp = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${serviceToken}`,
        "X-Request-Id": reqId,
      },
      body: JSON.stringify(cleanedPayload),
    });
  } catch (err) {
    return NextResponse.json(
      { error: "ingest_unreachable", detail: (err as Error).message },
      { status: 502 },
    );
  }

  // Pass through FastAPI's body + status. We strip hop-by-hop headers
  // implicitly because we re-build the response.
  const text = await resp.text();
  const out = new NextResponse(text || null, {
    status: resp.status,
    headers: { "Content-Type": resp.headers.get("content-type") ?? "application/json" },
  });
  out.headers.set("X-Request-Id", reqId);
  return out;
}
