// HS256 sign/verify for the ``gateway`` audience.
//
// Uses the Web Crypto API directly so we don't pull a JWT library into
// the Worker bundle. HS256 is just HMAC-SHA256 over base64url(header) +
// "." + base64url(payload), so the implementation fits in ~60 LoC.
//
// Two operations:
//   * mint() — sign a service token addressed to the BFF (audience=gateway
//              from the BFF's perspective: it's the audience the BFF is
//              "issuing to"; the gateway is also the issuer for inbound
//              checks — see the audience matrix in the architecture plan)
//   * verify() — check a token presented on the inbound /push route.
//
// The single shared HS256 secret (GATEWAY_SERVICE_TOKEN_SECRET) covers
// both directions because the BFF and gateway share trust at this layer
// and rotate the secret together via the Postgres-backed secret store.

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlEncodeStr(s: string): string {
  return b64urlEncode(enc.encode(s));
}

function b64urlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function importHmacKey(secret: string, usage: KeyUsage[]): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    usage,
  );
}

export interface MintArgs {
  secret: string;
  issuer: "gateway";
  targetAudience: "gateway" | "bff_user" | "ingest" | "worker";
  subject: string;       // user_id
  tenantId: string;
  ttlSeconds?: number;
  reqId?: string;
}

export async function mintHs256(args: MintArgs): Promise<string> {
  const ttl = args.ttlSeconds ?? 5 * 60;
  const iat = Math.floor(Date.now() / 1000);
  const header = b64urlEncodeStr(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64urlEncodeStr(
    JSON.stringify({
      iss: args.issuer,
      aud: args.targetAudience,
      sub: args.subject,
      tid: args.tenantId,
      jti: crypto.randomUUID(),
      iat,
      exp: iat + ttl,
      ...(args.reqId ? { req_id: args.reqId } : {}),
    }),
  );
  const signingInput = `${header}.${payload}`;
  const key = await importHmacKey(args.secret, ["sign"]);
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(signingInput));
  return `${signingInput}.${b64urlEncode(new Uint8Array(sigBuf))}`;
}

export interface VerifyArgs {
  secret: string;
  expectedAudience: "gateway";
  expectedIssuer?: "bff" | "gateway";
  leewaySeconds?: number;
}

export interface VerifiedClaims {
  iss: string;
  aud: string;
  sub: string;
  tid: string;
  jti: string;
  iat: number;
  exp: number;
  req_id?: string;
}

export async function verifyHs256(token: string, args: VerifyArgs): Promise<VerifiedClaims> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed token");
  const [header, payload, sig] = parts;
  const signingInput = `${header}.${payload}`;
  const key = await importHmacKey(args.secret, ["verify"]);
  const ok = await crypto.subtle.verify(
    "HMAC",
    key,
    b64urlDecode(sig),
    enc.encode(signingInput),
  );
  if (!ok) throw new Error("bad signature");
  const claims = JSON.parse(dec.decode(b64urlDecode(payload))) as VerifiedClaims;
  const leeway = args.leewaySeconds ?? 30;
  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== "number" || claims.exp + leeway < now) {
    throw new Error("expired");
  }
  if (typeof claims.iat !== "number" || claims.iat - leeway > now) {
    throw new Error("future-issued");
  }
  if (claims.aud !== args.expectedAudience) {
    throw new Error(`audience mismatch: got ${claims.aud}, expected ${args.expectedAudience}`);
  }
  if (args.expectedIssuer && claims.iss !== args.expectedIssuer) {
    throw new Error(`issuer mismatch: got ${claims.iss}, expected ${args.expectedIssuer}`);
  }
  return claims;
}
