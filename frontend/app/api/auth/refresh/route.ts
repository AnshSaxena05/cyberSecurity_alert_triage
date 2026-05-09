// POST /api/auth/refresh
// Reads the soc_refresh cookie, atomically rotates the refresh token,
// and issues a fresh access JWT. Reuse of an already-consumed refresh
// token burns the entire session family and returns 401.

import { NextRequest, NextResponse } from "next/server";

import { clearRefreshCookie, readRefreshCookieFromHeader, setRefreshCookie } from "@/lib/cookies";
import { mintAccessToken } from "@/lib/jwt";
import { rotateRefresh } from "@/lib/session";

export const runtime = "nodejs";

export async function POST(req: NextRequest): Promise<NextResponse> {
  const refreshToken = readRefreshCookieFromHeader(req.headers.get("cookie"));
  if (!refreshToken) {
    const res = NextResponse.json({ error: "missing_refresh" }, { status: 401 });
    clearRefreshCookie(res);
    return res;
  }

  const outcome = await rotateRefresh({ refreshToken });
  if (!outcome.ok) {
    const res = NextResponse.json(
      { error: "refresh_failed", reason: outcome.reason },
      { status: 401 },
    );
    clearRefreshCookie(res);
    return res;
  }

  const { token, expEpoch } = await mintAccessToken({
    userId: outcome.session.user_id,
    tenantId: outcome.session.tenant_id,
    role: outcome.session.role,
  });

  const res = NextResponse.json(
    { access_token: token, exp_epoch: expEpoch },
    { status: 200 },
  );
  setRefreshCookie(res, outcome.newRefreshToken);
  return res;
}
