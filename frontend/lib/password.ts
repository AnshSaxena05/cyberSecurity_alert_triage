// Password hashing. argon2id with conservative parameters.
//
// We deliberately don't expose the configuration knobs — all callers go
// through the same `hashPassword`/`verifyPassword` pair so we can tune
// memory/iterations centrally if a hardware upgrade demands it.

import argon2 from "argon2";

const HASH_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19_456,   // 19 MiB
  timeCost: 2,
  parallelism: 1,
} as const;

export async function hashPassword(plain: string): Promise<string> {
  return await argon2.hash(plain, HASH_OPTIONS);
}

export async function verifyPassword(plain: string, hash: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, plain);
  } catch {
    return false;
  }
}
