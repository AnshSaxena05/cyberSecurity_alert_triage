// One-shot CLI: seed (or upsert) an admin user.
//
// Usage:
//
//   ADMIN_EMAIL=admin@example.com \
//   ADMIN_PASSWORD=changeme123 \
//   ADMIN_TENANT_ID=acme \
//   ADMIN_ROLE=admin \
//   npx tsx scripts/seed-admin.ts
//
// Idempotent: if the email already exists the password and role are
// rotated to the new values. Safe to run on every deploy.
//
// NOTE: Uses pg and argon2 directly to avoid the `server-only` guard that
// the lib/ modules enforce (which is correct for Next.js routes but breaks
// this standalone tsx script).

import { config as loadEnv } from "dotenv";
loadEnv({ path: ".env.local" });
loadEnv();

import { Pool } from "pg";
import argon2 from "argon2";
import { randomUUID } from "crypto";

const pool = new Pool({ connectionString: process.env.POSTGRES_URL });

async function hashPassword(plain: string): Promise<string> {
  return argon2.hash(plain, {
    type: argon2.argon2id,
    memoryCost: 19_456,
    timeCost: 2,
    parallelism: 1,
  });
}

async function ensureUsersSchema(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id          TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::text,
      email       TEXT        NOT NULL UNIQUE,
      password_hash TEXT      NOT NULL,
      tenant_id   TEXT        NOT NULL DEFAULT 'default',
      role        TEXT        NOT NULL DEFAULT 'analyst',
      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

function required(name: string): string {
  const v = process.env[name];
  if (!v) {
    console.error(`missing required env var: ${name}`);
    process.exit(1);
  }
  return v!;
}

async function main() {
  const email = required("ADMIN_EMAIL").toLowerCase();
  const password = required("ADMIN_PASSWORD");
  const tenantId = process.env.ADMIN_TENANT_ID ?? "default";
  const role = process.env.ADMIN_ROLE ?? "admin";

  if (password.length < 8) {
    console.error("ADMIN_PASSWORD must be at least 8 characters.");
    process.exit(1);
  }

  await ensureUsersSchema();
  const passwordHash = await hashPassword(password);

  const existing = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
  if (existing.rows.length > 0) {
    const id = existing.rows[0].id;
    await pool.query(
      "UPDATE users SET password_hash = $1, tenant_id = $2, role = $3 WHERE id = $4",
      [passwordHash, tenantId, role, id],
    );
    console.log(`updated existing user: ${email} (id=${id})`);
  } else {
    const id = randomUUID();
    await pool.query(
      "INSERT INTO users (id, email, password_hash, tenant_id, role) VALUES ($1, $2, $3, $4, $5)",
      [id, email, passwordHash, tenantId, role],
    );
    console.log(`created user: ${email} (id=${id})`);
  }

  await pool.end();
  process.exit(0);
}

main().catch((err) => {
  console.error("seed-admin failed:", err);
  process.exit(1);
});
