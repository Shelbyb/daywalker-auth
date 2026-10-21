/** Starts the webhook delivery loop inside the server process (set WEBHOOK_WORKER=0 to disable). */
export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs" || process.env.WEBHOOK_WORKER === "0") return;
  const g = globalThis as { __dwWebhooks?: boolean };
  if (g.__dwWebhooks) return;
  g.__dwWebhooks = true;
  const { processDue, purgeOld } = await import("./lib/webhooks");
  const tick = () => processDue().catch((e) => console.error("[webhooks] worker", (e as Error).message));
  setInterval(tick, 15_000).unref();
  setInterval(() => purgeOld().catch(() => {}), 6 * 3_600_000).unref();
}
