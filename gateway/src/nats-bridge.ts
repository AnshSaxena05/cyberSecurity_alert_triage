// nats-bridge.ts is intentionally empty.
//
// We previously planned to open an outbound NATS WebSocket from inside the
// Durable Object. That approach has unresolved survivability concerns
// across DO eviction and is gated on a week-0 spike that we elected NOT
// to take.
//
// Architecture switched to **reverse-push fan-out** (Option 1 from the
// architecture trade-off note). The DO never talks to NATS; instead, the
// BFF subscribes to NATS and POSTs events to the DO's `/push` endpoint.
// On hibernation/eviction the inbound POST simply wakes the DO.
//
// This file is kept as a marker so future code that imports the previous
// bridge interface fails loudly, with a pointer to what replaced it.

export const REVERSE_PUSH_NOTE =
  "DO ↔ NATS bridge removed. Use reverse-push fan-out " +
  "(see frontend/lib/event-fanout.ts and gateway /push route).";

export function connectNats(): never {
  throw new Error(REVERSE_PUSH_NOTE);
}
