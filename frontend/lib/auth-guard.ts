// Bearer-token check for non-auth API routes.
// Returns the verified claims on success, or a NextResponse 401 to
// hand back to the caller on failure. Caller pattern:
//
//   const claims = await requireAccessToken(req);
//   if (claims instanceof NextResponse) return claims;

import "server-only";

import { NextRequest, NextResponse } from "next/server";

import { verifyAccessToken, type AccessTokenClaims } from "./jwt";
import { isJtiDenied } from "./session";

export async function requireAccessToken(
  req: NextRequest,
): Promise<AccessTokenClaims | NextResponse> {
  const auth = req.headers.get("authorization") ?? "";
  if (!auth.toLowerCase().startsWith("bearer ")) {
    return NextResponse.json({ error: "missing_bearer" }, { status: 401 });
  }
  const token = auth.slice("bearer ".length).trim();
  if (!token) {
    return NextResponse.json({ error: "empty_bearer" }, { status: 401 });
  }
  let claims: AccessTokenClaims;
  try {
    claims = await verifyAccessToken(token);
  } catch {
    return NextResponse.json({ error: "invalid_token" }, { status: 401 });
  }
  // Instant revocation deny-list (logout / lockout / role change).
  if (await isJtiDenied(claims.jti)) {
    return NextResponse.json({ error: "revoked_token" }, { status: 401 });
  }
  return claims;
}
