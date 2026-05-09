// Refresh-token cookie helpers. All in one place so the cookie-attribute
// invariants (HttpOnly, Secure, SameSite=Strict) cannot drift across
// routes.

import "server-only";

import type { NextResponse } from "next/server";

import { Config } from "./config";

const REFRESH_COOKIE = "soc_refresh";

export function setRefreshCookie(res: NextResponse, refreshToken: string): void {
  res.cookies.set({
    name: REFRESH_COOKIE,
    value: refreshToken,
    httpOnly: true,
    secure: Config.cookieSecure,
    sameSite: "strict",
    domain: Config.cookieDomain,
    path: "/api/auth/",          // refresh cookie only travels to auth routes
    maxAge: Config.refreshTokenTtlSeconds,
  });
}

export function clearRefreshCookie(res: NextResponse): void {
  res.cookies.set({
    name: REFRESH_COOKIE,
    value: "",
    httpOnly: true,
    secure: Config.cookieSecure,
    sameSite: "strict",
    domain: Config.cookieDomain,
    path: "/api/auth/",
    maxAge: 0,
  });
}

export function readRefreshCookieFromHeader(cookieHeader: string | null): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === REFRESH_COOKIE) {
      return rest.join("=");
    }
  }
  return null;
}
