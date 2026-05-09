// Read service-token secrets from Postgres.
//
// Schema (created by services._runtime.secret_store.py on first boot):
//
//   CREATE TABLE service_secrets (
//     audience        TEXT  PRIMARY KEY,
//     current_secret  TEXT  NOT NULL,
//     previous_secret TEXT,
//     rotated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
//   );
//
// We hold a per-audience cache so the hot path (mint a service token on
// every API call) doesn't hit Postgres. Cache entries refresh after
// `cacheTtlSeconds`; LISTEN/NOTIFY-driven invalidation lands when we wire
// the rotation watcher.

import "server-only";

import { queryOne } from "./db";

export interface SecretBundle {
  audience: string;
  current: string;
  previous: string | null;
  rotatedAtEpoch: number;
}

const cacheTtlSeconds = 60;

interface CacheEntry {
  bundle: SecretBundle;
  loadedAt: number;
}

const cache = new Map<string, CacheEntry>();

export async function getSecretBundle(audience: string): Promise<SecretBundle> {
  const now = Date.now() / 1000;
  const hit = cache.get(audience);
  if (hit && now - hit.loadedAt < cacheTtlSeconds) {
    return hit.bundle;
  }

  const row = await queryOne<{
    audience: string;
    current_secret: string;
    previous_secret: string | null;
    rotated_at_epoch: string;
  }>(
    `SELECT audience, current_secret, previous_secret,
            EXTRACT(EPOCH FROM rotated_at)::text AS rotated_at_epoch
       FROM service_secrets
      WHERE audience = $1`,
    [audience],
  );
  if (!row) {
    throw new Error(`unknown service-secret audience: ${audience}`);
  }

  const bundle: SecretBundle = {
    audience: row.audience,
    current: row.current_secret,
    previous: row.previous_secret,
    rotatedAtEpoch: parseFloat(row.rotated_at_epoch),
  };
  cache.set(audience, { bundle, loadedAt: now });
  return bundle;
}

export function invalidateSecretCache(audience?: string): void {
  if (audience) {
    cache.delete(audience);
  } else {
    cache.clear();
  }
}
