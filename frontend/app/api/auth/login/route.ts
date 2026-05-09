// POST /api/auth/login
// Body: { email, password }
// On success:
//   200 + JSON { access_token, exp_epoch, user: { id, email, tenant_id, role } }
//   Set-Cookie: soc_refresh=<family>.<jti>  (HttpOnly, Secure, SameSite=Strict)

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";

import { clearRefreshCookie, setRefreshCookie } from "@/lib/cookies";
import { mintAccessToken } from "@/lib/jwt";
import { startSession } from "@/lib/session";
import { findUserByEmail, recordLogin } from "@/lib/users";
import { verifyPassword } from "@/lib/password";

export const runtime = "nodejs";   // pg + ioredis + argon2 require Node, not Edge.

const LoginBody = z.object({
  email: z.string().email().max(254),
  password: z.string().min(8).max(256),
});

export async function POST(req: NextRequest): Promise<NextResponse> {
  let body: z.infer<typeof LoginBody>;
  try {
    body = LoginBody.parse(await req.json());
  } catch (err) {
    return NextResponse.json(
      { error: "invalid_request", detail: (err as Error).message },
      { status: 400 },
    );
  }

  const user = await findUserByEmail(body.email);
  // Always do the same amount of work whether or not the user exists, to
  // avoid timing-attack hints. We compute a verify against a fixed dummy
  // hash when the user is missing.
  const PLACEHOLDER_HASH =
    "$argon2id$v=19$m=19456,t=2,p=1$YWFhYWFhYWFhYWFhYWFhYQ$" +
    "fH9xxcQqQwk4Z8j6eYx0zAOQTXuQXTjE+aDz4xQHfeo";
  const passwordOk = user
    ? await verifyPassword(body.password, user.password_hash)
    : await verifyPassword(body.password, PLACEHOLDER_HASH);

  if (!user || !passwordOk) {
    const res = NextResponse.json({ error: "invalid_credentials" }, { status: 401 });
    clearRefreshCookie(res);
    return res;
  }

  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? undefined;
  const ua = req.headers.get("user-agent") ?? undefined;

  const { token, expEpoch } = await mintAccessToken({
    userId: user.id,
    tenantId: user.tenant_id,
    role: user.role ?? null,
  });
  const { refreshToken } = await startSession({
    userId: user.id,
    tenantId: user.tenant_id,
    role: user.role ?? null,
    ip,
    ua,
  });
  await recordLogin(user.id);

  const res = NextResponse.json(
    {
      access_token: token,
      exp_epoch: expEpoch,
      user: {
        id: user.id,
        email: user.email,
        tenant_id: user.tenant_id,
        role: user.role,
      },
    },
    { status: 200 },
  );
  setRefreshCookie(res, refreshToken);
  return res;
}
