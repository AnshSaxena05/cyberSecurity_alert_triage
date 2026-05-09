// Postgres connection pool. One pool per process, lazily constructed.
//
// Why pg here when the Python services use asyncpg? Because the BFF runs in
// a Node runtime and pg is the de-facto standard. Both clients connect to
// the same database — schemas are owned by Postgres, not by language.

import "server-only";

import { Pool } from "pg";

import { Config } from "./config";

let _pool: Pool | null = null;

export function pool(): Pool {
  if (_pool) return _pool;
  _pool = new Pool({
    connectionString: Config.postgresUrl,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
  });
  _pool.on("error", (err) => {
    // Idle-client errors must not crash the BFF — pg will reconnect.
    console.error("[db] idle client error:", err.message);
  });
  return _pool;
}

export async function query<T extends Record<string, unknown> = Record<string, unknown>>(
  sql: string,
  params: unknown[] = [],
): Promise<T[]> {
  const r = await pool().query(sql, params);
  return r.rows as T[];
}

export async function queryOne<T extends Record<string, unknown> = Record<string, unknown>>(
  sql: string,
  params: unknown[] = [],
): Promise<T | null> {
  const rows = await query<T>(sql, params);
  return rows[0] ?? null;
}

export async function tx<T>(fn: (q: typeof query) => Promise<T>): Promise<T> {
  const client = await pool().connect();
  try {
    await client.query("BEGIN");
    const txQuery: typeof query = async (sql, params = []) => {
      const r = await client.query(sql, params);
      return r.rows as never;
    };
    const out = await fn(txQuery);
    await client.query("COMMIT");
    return out;
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {
      /* ignore */
    }
    throw err;
  } finally {
    client.release();
  }
}
