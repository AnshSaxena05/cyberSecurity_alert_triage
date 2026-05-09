"use client";

// Minimal smoke-test login page. Real cockpit UI lands later — this is
// just enough to drive an end-to-end auth flow from the browser:
//
//   * POST /api/auth/login with email + password
//   * On 200, the access token + user profile come back. We hold them
//     in component state (intentionally NOT localStorage — see the
//     architecture plan §Q2 on token storage).
//   * The refresh token is set as an HttpOnly cookie by the BFF; this
//     UI never sees it.
//   * "Logout" calls /api/auth/logout which burns the session and
//     clears the cookie.

import { useState } from "react";

interface User {
  id: string;
  email: string;
  tenant_id: string;
  role: string | null;
}

interface LoginResponse {
  access_token: string;
  exp_epoch: number;
  user: User;
}

const BOX = {
  fontFamily: "ui-monospace, monospace",
  padding: "2rem",
  maxWidth: 560,
  lineHeight: 1.5,
} as const;

const INPUT = {
  display: "block",
  width: "100%",
  padding: "0.5rem",
  marginBottom: "0.75rem",
  fontFamily: "inherit",
  fontSize: "0.95rem",
  border: "1px solid #ccc",
  borderRadius: 4,
} as const;

const BTN = {
  padding: "0.5rem 1rem",
  fontFamily: "inherit",
  cursor: "pointer",
  border: "1px solid #333",
  background: "#111",
  color: "#fff",
  borderRadius: 4,
} as const;

export default function HomePage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [auth, setAuth] = useState<LoginResponse | null>(null);

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const resp = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
        credentials: "same-origin",
      });
      const body = await resp.json();
      if (!resp.ok) {
        setError(body.error ?? `login failed (${resp.status})`);
        return;
      }
      setAuth(body as LoginResponse);
      setPassword("");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function handleLogout() {
    if (!auth) return;
    setBusy(true);
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${auth.access_token}`,
        },
        credentials: "same-origin",
      });
      setAuth(null);
    } finally {
      setBusy(false);
    }
  }

  async function handleRequestTicket() {
    if (!auth) return;
    setBusy(true);
    setError(null);
    try {
      const resp = await fetch("/api/ws/ticket", {
        method: "POST",
        headers: { Authorization: `Bearer ${auth.access_token}` },
      });
      const body = await resp.json();
      if (!resp.ok) {
        setError(body.error ?? `ticket failed (${resp.status})`);
        return;
      }
      alert(
        `WS ticket: ${body.ticket}\n` +
          `Expires in ${body.expires_in_seconds}s.\n\n` +
          `Use it at: ws://localhost:8787/ws?t=${body.ticket}`,
      );
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (auth) {
    return (
      <main style={BOX}>
        <h1>SOC Triage</h1>
        <p>
          Signed in as <strong>{auth.user.email}</strong>
        </p>
        <pre style={{ background: "#f5f5f5", padding: "0.75rem", borderRadius: 4 }}>
          {JSON.stringify(auth.user, null, 2)}
        </pre>
        <p>
          <small>access token expires at: {new Date(auth.exp_epoch * 1000).toLocaleString()}</small>
        </p>
        <div style={{ display: "flex", gap: "0.5rem", marginTop: "1rem" }}>
          <button style={BTN} onClick={handleRequestTicket} disabled={busy}>
            Request WS ticket
          </button>
          <button style={BTN} onClick={handleLogout} disabled={busy}>
            Logout
          </button>
        </div>
        {error && (
          <p style={{ color: "#b00", marginTop: "1rem" }}>error: {error}</p>
        )}
      </main>
    );
  }

  return (
    <main style={BOX}>
      <h1>SOC Triage — sign in</h1>
      <p>
        BFF smoke-test login. Use the credentials you seeded with{" "}
        <code>make seed-admin</code>.
      </p>
      <form onSubmit={handleLogin}>
        <label>
          Email
          <input
            style={INPUT}
            type="email"
            required
            autoFocus
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={busy}
          />
        </label>
        <label>
          Password
          <input
            style={INPUT}
            type="password"
            required
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={busy}
          />
        </label>
        <button style={BTN} type="submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
      {error && (
        <p style={{ color: "#b00", marginTop: "1rem" }}>error: {error}</p>
      )}
    </main>
  );
}
