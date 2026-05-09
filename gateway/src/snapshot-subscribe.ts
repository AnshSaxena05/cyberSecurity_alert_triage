// Snapshot helper for late-joiners.
//
// In the reverse-push fan-out architecture (Option 1) the DO no longer
// subscribes to NATS directly. Instead it:
//
//   1) Reads a snapshot from the BFF: GET /api/alerts/{id}/snapshot
//      → { last_seq, current_phase }
//   2) Renders that to the browser immediately so the UI isn't blank.
//   3) Registers with the BFF watcher registry; the BFF's NATS-fan-out
//      service starts pushing every subsequent event to the DO.
//
// The DO does not need a JetStream start-sequence anymore (the registry
// is consumed by the fan-out service, which subscribes from "now"). The
// only correctness guarantee that requires last_seq is on the *browser*
// side: the UI tracks the highest event_seq it has seen and ignores
// duplicates if the fan-out happens to redeliver during a reconnect.

export interface Snapshot {
  alert_id: string;
  last_seq: number;
  current_phase: string | null;
}

export async function fetchSnapshot(args: {
  bffBaseUrl: string;
  alertId: string;
  serviceToken: string;
}): Promise<Snapshot> {
  const url = new URL(`/api/alerts/${args.alertId}/snapshot`, args.bffBaseUrl);
  const resp = await fetch(url, {
    method: "GET",
    headers: { Authorization: `Bearer ${args.serviceToken}` },
  });
  if (!resp.ok) {
    throw new Error(`snapshot fetch failed: ${resp.status}`);
  }
  const body = (await resp.json()) as { last_seq?: number; current_phase?: string | null };
  return {
    alert_id: args.alertId,
    last_seq: typeof body.last_seq === "number" ? body.last_seq : 0,
    current_phase: body.current_phase ?? null,
  };
}
