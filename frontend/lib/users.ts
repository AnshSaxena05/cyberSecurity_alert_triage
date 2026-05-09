// User store. Postgres-backed.
//
// Schema (created on demand by ensureUsersSchema()):
//
//   CREATE TABLE users (
//     id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
//     email         TEXT         UNIQUE NOT NULL,
//     password_hash TEXT         NOT NULL,
//     tenant_id     TEXT         NOT NULL,
//     role          TEXT         DEFAULT 'analyst',
//     created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
//     last_login_at TIMESTAMPTZ
//   );
//   CREATE INDEX users_tenant_id_idx ON users(tenant_id);
//
// Passwords are hashed with argon2 (id, the recommended variant). See
// password.ts for the wrappers.

import "server-only";

import { query, queryOne } from "./db";

export interface User {
  id: string;
  email: string;
  tenant_id: string;
  role: string | null;
}

interface UserRow extends User {
  password_hash: string;
}

const SCHEMA_SQL = `
  CREATE EXTENSION IF NOT EXISTS pgcrypto;

  CREATE TABLE IF NOT EXISTS users (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT         UNIQUE NOT NULL,
    password_hash TEXT         NOT NULL,
    tenant_id     TEXT         NOT NULL,
    role          TEXT         DEFAULT 'analyst',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
  );
  CREATE INDEX IF NOT EXISTS users_tenant_id_idx ON users(tenant_id);
`;

let schemaEnsured = false;

export async function ensureUsersSchema(): Promise<void> {
  if (schemaEnsured) return;
  await query(SCHEMA_SQL);
  schemaEnsured = true;
}

export async function findUserByEmail(email: string): Promise<UserRow | null> {
  await ensureUsersSchema();
  return await queryOne<UserRow>(
    `SELECT id, email, password_hash, tenant_id, role
       FROM users
      WHERE email = $1`,
    [email.toLowerCase()],
  );
}

export async function createUser(args: {
  email: string;
  passwordHash: string;
  tenantId: string;
  role?: string | null;
}): Promise<User> {
  await ensureUsersSchema();
  const row = await queryOne<User>(
    `INSERT INTO users (email, password_hash, tenant_id, role)
     VALUES ($1, $2, $3, COALESCE($4, 'analyst'))
     RETURNING id, email, tenant_id, role`,
    [args.email.toLowerCase(), args.passwordHash, args.tenantId, args.role ?? null],
  );
  if (!row) {
    throw new Error("user insert returned no row");
  }
  return row;
}

export async function recordLogin(userId: string): Promise<void> {
  await query(`UPDATE users SET last_login_at = NOW() WHERE id = $1`, [userId]);
}
