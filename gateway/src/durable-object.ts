// AnalystSession Durable Object — reverse-push fan-out edition.
//
// Per-analyst stateful actor that owns:
//   1. The browser WebSocket (terminated here, not at FastAPI).
//   2. A registration in the BFF's watcher registry per (do_id, alert_id)
//      pair, so the BFF's NATS-fan-out service knows where to push events.
//   3. A debounced cancel-on-close that POSTs ``triage.cancel`` to the
//      BFF (which forwards to NATS) when the WS closes without a verdict.
//
// The DO does NOT hold any outbound NATS / long-lived broker connection.
// All inbound triage events arrive as HTTP POSTs to ``/`` (routed by the
// parent Worker via ``env.ANALYST_SESSION.idFromString(do_id).fetch``).
//
// Hibernation: the WebSocket-Hibernation API keeps the WS alive across
// idle. When the BFF POSTs an event, CF wakes the DO. The DO calls
// ``state.getWebSockets()`` to get the active WSes and forwards the
// event JSON.

import { fetchSnapshot, type Snapshot } from "./snapshot-subscribe";
import { mintHs256, verifyHs256 } from "./jwt";
import type {
  ClientMessage,
  Env,
  PushEnvelope,
  ServerMessage,
  TicketRedemption,
  WatchRegistration,
} from "./types";

const CANCEL_GRACE_MS = 5_000;
const SERVICE_TOKEN_TTL_SEC = 5 * 60;

interface PendingCancel {
  alertId: string;
  timer: ReturnType<typeof setTimeout>;
}

export class AnalystSession implements DurableObject {
  private state: DurableObjectState;
  private env: Env;
  private ticket: TicketRedemption | null = null;
  private watchedAlerts = new Set<string>();
  private pendingCancels = new Map<string, PendingCancel>();

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  // -------------------------------------------------------------------
  // fetch() — multiplexed by URL path
  // -------------------------------------------------------------------

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/push") {
      return await this.handlePush(req);
    }
    // Default path: WS upgrade with ticket.
    return await this.handleUpgrade(req);
  }

  // -------------------------------------------------------------------
  // Browser-side: WebSocket upgrade
  // -------------------------------------------------------------------

  private async handleUpgrade(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const ticketStr = url.searchParams.get("t") ?? "";
    if (!ticketStr) {
      return new Response("missing ticket", { status: 401 });
    }

    let ticket: TicketRedemption;
    try {
      ticket = await this.redeemTicket(ticketStr);
    } catch (err) {
      return new Response(`ticket rejected: ${(err as Error).message}`, { status: 401 });
    }
    this.ticket = ticket;

    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];

    // Hibernation API: CF keeps the WS alive even when the DO hibernates.
    // Inbound frames or inbound HTTP (our /push) wake us up.
    this.state.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  // -------------------------------------------------------------------
  // Hibernation handlers
  // -------------------------------------------------------------------

  async webSocketMessage(ws: WebSocket, raw: string | ArrayBuffer): Promise<void> {
    if (typeof raw !== "string") return;
    let msg: ClientMessage;
    try {
      msg = JSON.parse(raw) as ClientMessage;
    } catch {
      return this.sendError(ws, "invalid_json");
    }
    if (!this.ticket) {
      return this.sendError(ws, "session_not_initialised");
    }

    switch (msg.type) {
      case "watch":
        await this.handleWatch(ws, msg.alert_id);
        break;
      case "unwatch":
        await this.handleUnwatch(msg.alert_id);
        break;
      case "ping":
        ws.send(JSON.stringify({ type: "pong" } satisfies { type: "pong" }));
        break;
      default:
        this.sendError(ws, "unknown_type");
    }
  }

  async webSocketClose(_ws: WebSocket, _code: number, _reason: string, _wasClean: boolean) {
    // Schedule cancellation for any in-flight alerts (debounced 5 s grace
    // so a quick tab-reopen doesn't kill an in-progress triage).
    for (const alertId of this.watchedAlerts) {
      this.scheduleCancel(alertId);
    }
    // Tell the BFF to drop our entire registration so future events stop
    // flowing. This is best-effort — if the BFF is briefly unreachable the
    // entries simply expire by TTL.
    if (this.ticket) {
      void this.callBff("/api/internal/disconnect", {
        do_id: this.state.id.toString(),
        user_id: this.ticket.user_id,
      });
    }
    this.watchedAlerts.clear();
  }

  async webSocketError(ws: WebSocket, _err: unknown) {
    return this.webSocketClose(ws, 1011, "error", false);
  }

  // -------------------------------------------------------------------
  // watch / unwatch — register with the BFF watcher registry
  // -------------------------------------------------------------------

  private async handleWatch(ws: WebSocket, alertId: string) {
    if (!this.ticket) return;
    if (this.watchedAlerts.has(alertId)) return;

    // If a cancel was queued for this alert (user closed and reopened),
    // abort it before the grace window expires.
    this.cancelScheduledCancel(alertId);

    let snapshot: Snapshot;
    try {
      snapshot = await fetchSnapshot({
        bffBaseUrl: this.env.SOC_BFF_BASE_URL,
        alertId,
        serviceToken: await this.gatewayServiceToken(),
      });
    } catch (err) {
      return this.sendError(ws, "snapshot_failed", (err as Error).message);
    }

    // Tell the browser the current state so its UI isn't blank while we
    // wait for the next event.
    this.send(ws, {
      type: "snapshot",
      alert_id: alertId,
      last_seq: snapshot.last_seq,
      current_phase: snapshot.current_phase,
    });

    // Register with the BFF. Subsequent events for ``alert_id`` will be
    // POSTed to ``push_url?do=<this DO id>``.
    const registration: WatchRegistration = {
      do_id: this.state.id.toString(),
      user_id: this.ticket.user_id,
      tenant_id: this.ticket.tenant_id,
      alert_id: alertId,
      push_url: `${this.env.GATEWAY_PUBLIC_URL.replace(/\/+$/, "")}/push`,
    };
    const ok = await this.callBff("/api/internal/watch", registration);
    if (!ok) {
      return this.sendError(ws, "registration_failed");
    }
    this.watchedAlerts.add(alertId);
  }

  private async handleUnwatch(alertId: string) {
    if (!this.watchedAlerts.has(alertId)) return;
    if (!this.ticket) return;
    this.watchedAlerts.delete(alertId);
    // Best-effort de-register; entries expire by TTL anyway.
    void this.callBff("/api/internal/unwatch", {
      do_id: this.state.id.toString(),
      alert_id: alertId,
    });
  }

  // -------------------------------------------------------------------
  // /push — inbound from the BFF fan-out service
  // -------------------------------------------------------------------

  private async handlePush(req: Request): Promise<Response> {
    // Verify the BFF's service token before touching the body.
    const auth = req.headers.get("authorization") ?? "";
    const token = auth.toLowerCase().startsWith("bearer ")
      ? auth.slice("bearer ".length).trim()
      : "";
    const secret = this.env.GATEWAY_SERVICE_TOKEN_SECRET;
    if (!secret) {
      return new Response("gateway secret unset", { status: 503 });
    }
    if (!token) {
      return new Response("missing service token", { status: 401 });
    }
    try {
      await verifyHs256(token, {
        secret,
        expectedAudience: "gateway",
        expectedIssuer: "bff",
      });
    } catch (err) {
      return new Response(`invalid service token: ${(err as Error).message}`, { status: 401 });
    }

    let envelope: PushEnvelope;
    try {
      envelope = (await req.json()) as PushEnvelope;
    } catch {
      return new Response("invalid json", { status: 400 });
    }

    const sockets = this.state.getWebSockets();
    if (sockets.length === 0) {
      // No live WS — the user disconnected or evicted. Tell the fan-out
      // to stop pushing so its next iteration removes us from the registry.
      return new Response("no active websocket", { status: 410 });
    }

    let body: ServerMessage | null = null;
    switch (envelope.kind) {
      case "phase":
      case "token":
        if (!envelope.event) return new Response("missing event", { status: 400 });
        body = { type: "event", event: envelope.event };
        break;
      case "cancel":
        // We don't have a separate frame for cancel from the server side —
        // reuse the event channel with a synthesized phase=cancelled.
        if (!envelope.cancel) return new Response("missing cancel", { status: 400 });
        body = {
          type: "event",
          event: {
            kind: "phase",
            alert_id: envelope.cancel.alert_id,
            tenant_id: this.ticket?.tenant_id ?? "",
            event_seq: 0,
            phase: "cancelled",
            emitted_at: new Date().toISOString(),
          },
        };
        break;
      case "revoked":
        body = { type: "revoked" };
        break;
      default:
        return new Response("unknown kind", { status: 400 });
    }

    for (const ws of sockets) {
      try {
        ws.send(JSON.stringify(body));
        // Revocation = forced close.
        if (envelope.kind === "revoked") {
          ws.close(4401, "revoked");
        }
      } catch {
        /* ignore single-WS failures */
      }
    }
    return new Response(null, { status: 204 });
  }

  // -------------------------------------------------------------------
  // Cancel-on-close (debounced)
  // -------------------------------------------------------------------

  private scheduleCancel(alertId: string) {
    if (!this.ticket || this.pendingCancels.has(alertId)) return;
    const timer = setTimeout(() => {
      void this.fireCancel(alertId);
    }, CANCEL_GRACE_MS);
    this.pendingCancels.set(alertId, { alertId, timer });
  }

  private cancelScheduledCancel(alertId: string) {
    const pending = this.pendingCancels.get(alertId);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.pendingCancels.delete(alertId);
  }

  private async fireCancel(alertId: string) {
    if (!this.ticket) return;
    this.pendingCancels.delete(alertId);
    void this.callBff("/api/internal/cancel", {
      do_id: this.state.id.toString(),
      tenant_id: this.ticket.tenant_id,
      user_id: this.ticket.user_id,
      alert_id: alertId,
    });
  }

  // -------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------

  private async redeemTicket(ticket: string): Promise<TicketRedemption> {
    const url = new URL("/api/ws/redeem", this.env.SOC_BFF_BASE_URL);
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${await this.gatewayServiceToken()}`,
      },
      body: JSON.stringify({ ticket }),
    });
    if (!resp.ok) {
      throw new Error(`redeem failed: ${resp.status}`);
    }
    return (await resp.json()) as TicketRedemption;
  }

  private async callBff(path: string, body: unknown): Promise<boolean> {
    try {
      const url = new URL(path, this.env.SOC_BFF_BASE_URL);
      const resp = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${await this.gatewayServiceToken()}`,
        },
        body: JSON.stringify(body),
      });
      return resp.ok;
    } catch (err) {
      console.error("[do] callBff failed:", path, (err as Error).message);
      return false;
    }
  }

  private async gatewayServiceToken(): Promise<string> {
    const secret = this.env.GATEWAY_SERVICE_TOKEN_SECRET;
    if (!secret) {
      throw new Error("GATEWAY_SERVICE_TOKEN_SECRET unset");
    }
    return await mintHs256({
      secret,
      issuer: "gateway",
      // Tokens minted FROM the gateway TO the BFF carry audience=gateway —
      // the BFF's verifyServiceToken(token, "gateway") will accept them.
      targetAudience: "gateway",
      subject: this.ticket?.user_id ?? "anon",
      tenantId: this.ticket?.tenant_id ?? "anon",
      ttlSeconds: SERVICE_TOKEN_TTL_SEC,
    });
  }

  private send(ws: WebSocket, msg: ServerMessage) {
    try {
      ws.send(JSON.stringify(msg));
    } catch {
      /* ignore */
    }
  }

  private sendError(ws: WebSocket, code: string, detail?: string) {
    this.send(ws, { type: "error", code, detail });
  }
}
