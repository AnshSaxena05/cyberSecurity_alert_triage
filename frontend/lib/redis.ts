// Redis client. One connection per process; commands multiplex.

import "server-only";

import Redis from "ioredis";

import { Config } from "./config";

let _client: Redis | null = null;

export function redis(): Redis {
  if (_client) return _client;
  _client = new Redis(Config.redisUrl, {
    // Don't crash the BFF if Redis is briefly unreachable on boot — auth
    // routes will surface 503 to the caller, who can retry.
    maxRetriesPerRequest: 5,
    enableReadyCheck: true,
    lazyConnect: false,
  });
  _client.on("error", (err) => {
    console.error("[redis] error:", err.message);
  });
  return _client;
}
