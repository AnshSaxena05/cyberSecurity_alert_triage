// HS256 sign/verify for both planes:
//   1) external user JWT  (audience = bff_user)   — given to the browser
//   2) internal service JWTs (audience = ingest | worker | gateway) — given to backends
//
// Both planes draw secrets from the same Postgres-backed store via secrets.ts.
// Distinct audiences = distinct secrets, so a compromise of (say) the worker
// cannot mint tokens that ingest or the BFF user plane will accept.
//
// Verification accepts both `current` and `previous` secrets during the
// 1-hour rotation overlap window, matching the worker-side semantics.

import "server-only";

import { randomBytes } from "node:crypto";

import { SignJWT, jwtVerify } from "jose";

import { Config } from "./config";
import { getSecretBundle } from "./secrets";

export interface AccessTokenClaims {
  sub: string;            // user_id
  tid: string;            // tenant_id
  role: string | null;
  jti: string;
  iat: number;
  exp: number;
  iss: "bff";
  aud: "bff_user";
}

export interface ServiceTokenClaims {
  iss: "bff";
  sub: string;
  tid: string;
  aud: "ingest" | "worker" | "gateway";
  jti: string;
  iat: number;
  exp: number;
  role?: string | null;
  req_id?: string;
}

function newJti(): string {
  return randomBytes(16).toString("base64url");
}

// ----------------------------------------------------------------------
// External user token (Browser ↔ BFF)
// ----------------------------------------------------------------------

export async function mintAccessToken(args: {
  userId: string;
  tenantId: string;
  role?: string | null;
}): Promise<{ token: string; jti: string; expEpoch: number }> {
  const bundle = await getSecretBundle(Config.audiences.bffUser);
  const jti = newJti();
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + Config.accessTokenTtlSeconds;
  const token = await new SignJWT({
    tid: args.tenantId,
    role: args.role ?? null,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("bff")
    .setAudience(Config.audiences.bffUser)
    .setSubject(args.userId)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .setJti(jti)
    .sign(new TextEncoder().encode(bundle.current));
  return { token, jti, expEpoch: exp };
}

export async function verifyAccessToken(token: string): Promise<AccessTokenClaims> {
  const bundle = await getSecretBundle(Config.audiences.bffUser);

  const tryWith = async (secret: string) =>
    jwtVerify(token, new TextEncoder().encode(secret), {
      issuer: "bff",
      audience: Config.audiences.bffUser,
      clockTolerance: 30,
      requiredClaims: ["sub", "exp", "iat", "jti"],
    });

  try {
    const r = await tryWith(bundle.current);
    return r.payload as unknown as AccessTokenClaims;
  } catch (errCurrent) {
    if (bundle.previous) {
      try {
        const r = await tryWith(bundle.previous);
        return r.payload as unknown as AccessTokenClaims;
      } catch {
        /* fall through */
      }
    }
    throw errCurrent;
  }
}

// ----------------------------------------------------------------------
// Internal service token (BFF → FastAPI / worker)
// ----------------------------------------------------------------------

export async function mintServiceToken(args: {
  targetAudience: "ingest" | "worker" | "gateway";
  userId: string;
  tenantId: string;
  role?: string | null;
  reqId?: string;
}): Promise<string> {
  const bundle = await getSecretBundle(args.targetAudience);
  const jti = newJti();
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 5 * 60; // 5 minutes — short by design
  return await new SignJWT({
    tid: args.tenantId,
    role: args.role ?? null,
    req_id: args.reqId,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("bff")
    .setAudience(args.targetAudience)
    .setSubject(args.userId)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .setJti(jti)
    .sign(new TextEncoder().encode(bundle.current));
}

export async function verifyServiceToken(
  token: string,
  expectedAudience: "ingest" | "worker" | "gateway",
): Promise<ServiceTokenClaims> {
  const bundle = await getSecretBundle(expectedAudience);
  const tryWith = async (secret: string) =>
    jwtVerify(token, new TextEncoder().encode(secret), {
      issuer: "bff",
      audience: expectedAudience,
      clockTolerance: 30,
      requiredClaims: ["sub", "exp", "iat", "jti"],
    });
  try {
    const r = await tryWith(bundle.current);
    return r.payload as unknown as ServiceTokenClaims;
  } catch (errCurrent) {
    if (bundle.previous) {
      try {
        const r = await tryWith(bundle.previous);
        return r.payload as unknown as ServiceTokenClaims;
      } catch {
        /* fall through */
      }
    }
    throw errCurrent;
  }
}
