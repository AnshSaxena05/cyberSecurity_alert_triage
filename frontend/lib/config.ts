// Runtime configuration loaded from environment variables.
//
// Centralised so the rest of the codebase doesn't sprinkle process.env reads
// through business logic. All values are validated lazily; reading any
// `Config.X` outside a request will throw if the env var is missing.

import "server-only";

function required(name: string): string {
  const v = process.env[name];
  if (!v) {
    throw new Error(`missing required env var: ${name}`);
  }
  return v;
}

function optional(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

function intOr(name: string, fallback: number): number {
  const v = process.env[name];
  if (!v) return fallback;
  const n = parseInt(v, 10);
  if (Number.isNaN(n) || n <= 0) return fallback;
  return n;
}

export const Config = {
  // Backends
  socApiBaseUrl: optional("SOC_API_BASE_URL", "http://localhost:8000"),
  natsUrl: optional("NATS_URL", "nats://localhost:4222"),
  redisUrl: optional("REDIS_URL", "redis://localhost:6379/0"),
  postgresUrl: optional(
    "POSTGRES_URL",
    "postgresql://soc:soc@localhost:5432/soc_checkpoint",
  ),

  // Token lifetimes
  accessTokenTtlSeconds: intOr("ACCESS_TOKEN_TTL_SECONDS", 15 * 60),
  refreshTokenTtlSeconds: intOr("REFRESH_TOKEN_TTL_SECONDS", 7 * 24 * 60 * 60),
  wsTicketTtlSeconds: intOr("WS_TICKET_TTL_SECONDS", 60),

  // Cookie scope
  cookieDomain: optional("COOKIE_DOMAIN", "localhost"),
  cookieSecure: (process.env.COOKIE_SECURE ?? "false").toLowerCase() === "true",

  // Audience names — must match services/_runtime/secret_store.py DEFAULT_AUDIENCES
  audiences: {
    bffUser: "bff_user",
    ingest: "ingest",
    worker: "worker",
    gateway: "gateway",
  },

  // NATS subject prefixes
  revocationSubjectPrefix: optional("REVOCATION_SUBJECT_PREFIX", "auth.revocations.v1"),
} as const;

// Throw fast if absolutely required values are missing on cold start.
export function assertConfig(): void {
  required("SOC_API_BASE_URL");
}
