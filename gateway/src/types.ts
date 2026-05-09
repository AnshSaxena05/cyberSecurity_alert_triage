// Shared interfaces between the Worker entry, the DO, and the helpers.

export interface Env {
  ANALYST_SESSION: DurableObjectNamespace;

  // Public vars (wrangler.toml)
  SOC_BFF_BASE_URL: string;
  GATEWAY_PUBLIC_URL: string;     // e.g. https://gateway.example.com — reported back to BFF as push_url

  // Secrets (wrangler secret put)
  // HS256 secret for the ``gateway`` audience. Used to sign service tokens
  // when calling the BFF (/api/ws/redeem, /api/internal/{watch,unwatch,disconnect})
  // and to verify the inbound /push token the BFF presents.
  GATEWAY_SERVICE_TOKEN_SECRET?: string;
}

export interface TicketRedemption {
  user_id: string;
  tenant_id: string;
  role: string | null;
}

// Mirror of schemas/v1/triage_event.py::PhaseEvent / TokenEvent envelopes.
export interface PhaseEvent {
  kind: "phase";
  alert_id: string;
  tenant_id: string;
  event_seq: number;
  phase: string;
  emitted_at: string;
  detail?: Record<string, unknown> | null;
  trace_id?: string | null;
}

export interface TokenEvent {
  kind: "token";
  alert_id: string;
  tenant_id: string;
  event_seq: number;
  emitted_at: string;
  node: string;
  text: string;
}

export type TriageEvent = PhaseEvent | TokenEvent;

// Browser → DO message envelope. All inbound WS messages are JSON.
export type ClientMessage =
  | { type: "watch"; alert_id: string }
  | { type: "unwatch"; alert_id: string }
  | { type: "ping" };

// DO → Browser envelope. Mirrors the triage event shapes plus a snapshot
// frame emitted on initial subscribe.
export type ServerMessage =
  | { type: "snapshot"; alert_id: string; last_seq: number; current_phase: string | null }
  | { type: "event"; event: TriageEvent }
  | { type: "revoked" }
  | { type: "error"; code: string; detail?: string };

// ---------------------------------------------------------------------------
// Reverse-push fan-out — BFF → Gateway → DO contract.
// ---------------------------------------------------------------------------

/**
 * Body the BFF sends when a triage event must be delivered to a DO.
 * The Worker uses ``do_id`` (query param) to address the DO via RPC; the
 * payload here is what the DO forwards to the browser WS.
 */
export interface PushEnvelope {
  kind: "phase" | "token" | "cancel" | "revoked";
  alert_id?: string;
  event?: TriageEvent;            // for kind=phase/token
  cancel?: { alert_id: string }; // for kind=cancel
  revoked?: { user_id: string }; // for kind=revoked
}

/**
 * Body the DO sends to the BFF when the browser asks to watch an alert.
 * The BFF stores this in the watcher registry; subsequent events for
 * ``alert_id`` will be POSTed to ``push_url`` with header
 * ``X-DO-Id: <do_id>`` so the Worker can route the call to this DO.
 */
export interface WatchRegistration {
  do_id: string;          // DurableObjectId.toString()
  user_id: string;
  tenant_id: string;
  alert_id: string;
  push_url: string;       // public Worker URL e.g. https://gateway.example.com/push
}

export interface UnwatchRequest {
  do_id: string;
  alert_id: string;
}

export interface DisconnectRequest {
  do_id: string;
  user_id: string;
}
