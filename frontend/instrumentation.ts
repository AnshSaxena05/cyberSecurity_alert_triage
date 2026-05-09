// Next.js boot hook. Runs once per server process at startup.
//
// We use this to start the event fan-out service. Module is server-only;
// Next.js will ignore it on the client bundle.
//
// See https://nextjs.org/docs/app/building-your-application/optimizing/instrumentation

export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  const { startEventFanout } = await import("./lib/event-fanout");
  await startEventFanout();
}
