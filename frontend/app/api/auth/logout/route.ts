// POST /api/auth/logout
// 1. Read the access token from Authorization header (if present) so we
//    can also deny its jti for the rest of its TTL.
// 2. End the session in Redis (deletes session:{user_id} and burns the
//    family's refresh tokens).
// 3. Publish auth.revocations.v1.{tenant}.{user} on NATS so every
//    Cloudflare DO subscribed to that subject force-closes any matching
//    open WebSocket within ~1s.
// 4. Clear the refresh cookie.

import { NextRequest, NextResponse } from "next/server";

import { clearRefreshCookie } from "@/lib/cookies";
import { verifyAccessToken } from "@/lib/jwt";
import { publishRevocation } from "@/lib/nats";
import { denyJti, endSession } from "@/lib/session";

export const runtime = "nodejs";

export async function POST(req: NextRequest): Promise<NextResponse> {
  const auth = req.headers.get("authorization") ?? "";
  const accessToken = auth.toLowerCase().startsWith("bearer ")
    ? auth.slice("bearer ".length).trim()
    : "";

  let userId: string | null = null;
  let tenantId: string | null = null;
  let jti: string | null = null;

  if (accessToken) {
    try {
      const claims = await verifyAccessToken(accessToken);
      userId = claims.sub;
      tenantId = claims.tid;
      jti = claims.jti;
    } catch {
      // Logout with an expired/invalid token is still meaningful — we have
      // the cookie. We just can't burn the access JWT specifically.
    }
  }

  // If we couldn't recover the user from the token, we have nothing to
  // burn. Still clear the cookie so the browser doesn't hold a refresh.
  if (!userId) {
    const res = NextResponse.json({ ok: true }, { status: 200 });
    clearRefreshCookie(res);
    return res;
  }

  // 1) Tear down the session record + refresh family.
  const session = await endSession(userId);

  // 2) Add the access JWT's jti to the deny-list so the next API call from
  // a stolen token fails immediately rather than waiting for TTL.
  if (jti) {
    await denyJti(jti);
  }

  // 3) Broadcast revocation. Best-effort — failures don't block logout.
  if (tenantId ?? session?.tenant_id) {
    await publishRevocation({
      tenantId: tenantId ?? session!.tenant_id,
      userId,
      reason: "logout",
    });
  }

  const res = NextResponse.json({ ok: true }, { status: 200 });
  clearRefreshCookie(res);
  return res;
}
