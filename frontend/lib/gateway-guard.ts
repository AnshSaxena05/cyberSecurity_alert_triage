// Auth guard for /api/internal/* routes — requires a service JWT
// addressed to the gateway audience, signed by the gateway's HS256
// secret. This is the inverse of the token the BFF mints when calling
// the DO's /push: same audience, same secret, different direction.

import "server-only";

import { NextRequest, NextResponse } from "next/server";

import { Config } from "./config";
import { verifyServiceToken, type ServiceTokenClaims } from "./jwt";

export async function requireGatewayToken(
  req: NextRequest,
): Promise<ServiceTokenClaims | NextResponse> {
  const auth = req.headers.get("authorization") ?? "";
  if (!auth.toLowerCase().startsWith("bearer ")) {
    return NextResponse.json({ error: "missing_bearer" }, { status: 401 });
  }
  const token = auth.slice("bearer ".length).trim();
  if (!token) {
    return NextResponse.json({ error: "empty_bearer" }, { status: 401 });
  }
  try {
    return await verifyServiceToken(token, Config.audiences.gateway);
  } catch {
    return NextResponse.json({ error: "invalid_token" }, { status: 401 });
  }
}
