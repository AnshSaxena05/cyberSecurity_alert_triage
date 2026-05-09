// Worker entry. Routes:
//
//   GET  /healthz           → 200 OK (liveness)
//   GET  /ws?t=<ticket>     → WebSocket upgrade, routed to AnalystSession DO
//                              by ticket-derived id (DO redeems ticket
//                              against the BFF inside fetch()).
//   POST /push?do=<id>      → BFF fan-out push. Verifies the gateway
//                              service JWT, then forwards the request
//                              into the named DO via RPC. The DO's
//                              fetch() handler emits the event on the
//                              live WebSocket.
//
// Eviction model: the DO is woken by the inbound /push fetch — that's
// the entire point of switching off the NATS-from-DO design. If the DO
// has been fully evicted (not just hibernated), the fetch creates a
// fresh DO instance with no in-RAM state; the next inbound POST simply
// returns 410 (no active websocket), and the BFF removes the watcher
// entry from its registry.

import type { Env } from "./types";

export { AnalystSession } from "./durable-object";

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/healthz") {
      return new Response("ok", { status: 200 });
    }

    if (url.pathname === "/ws") {
      const upgrade = req.headers.get("Upgrade")?.toLowerCase();
      if (upgrade !== "websocket") {
        return new Response("expected websocket upgrade", { status: 400 });
      }
      const ticket = url.searchParams.get("t") ?? "";
      if (!ticket) {
        return new Response("missing ticket", { status: 401 });
      }
      // Stable per-ticket DO id. The DO redeems the ticket inside fetch(),
      // and the same DO instance handles every subsequent /push call from
      // the BFF (because /push includes the same ?do= id in its query).
      const id = env.ANALYST_SESSION.idFromName(`ticket:${ticket}`);
      const stub = env.ANALYST_SESSION.get(id);
      return stub.fetch(req);
    }

    if (url.pathname === "/push") {
      const doIdStr = url.searchParams.get("do") ?? "";
      if (!doIdStr) {
        return new Response("missing do id", { status: 400 });
      }
      // We don't verify the inbound BFF token here — the DO does it after
      // routing. Centralising the check inside the DO means a single code
      // path for token rotation. The Worker layer's only job is routing.
      let id;
      try {
        id = env.ANALYST_SESSION.idFromString(doIdStr);
      } catch {
        return new Response("invalid do id", { status: 400 });
      }
      const stub = env.ANALYST_SESSION.get(id);
      return stub.fetch(req);
    }

    return new Response("not found", { status: 404 });
  },
};
