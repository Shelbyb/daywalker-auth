/** Starts the webhook delivery loop inside the server process (set WEBHOOK_WORKER=0 to disable). */
export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs" || process.env.WEBHOOK_WORKER === "0") return;
  const g = globalThis as { __dwWebhooks?: boolean };
  if (g.__dwWebhooks) return;
  g.__dwWebhooks = true;
  const { processDue, purgeOld } = await import("./lib/webhooks");
  const { purgeRetiredKeys } = await import("./lib/auth/keys");
  const { purgeAudit } = await import("./lib/audit");
  const { pushDue } = await import("./lib/audit-export");
  const { purgePlatformAudit } = await import("./lib/platform-audit");
  const { purgeDueDeletions } = await import("./lib/auth/account-deletion");
  const tick = () => processDue().catch((e) => console.error("[webhooks] worker", (e as Error).message));
  setInterval(tick, 15_000).unref();
  setInterval(() => purgeDueDeletions().catch((e) => console.error("[deletion] job", (e as Error).message)), 10 * 60_000).unref();
  setInterval(() => purgeOld().catch(() => {}), 6 * 3_600_000).unref();
  setInterval(() => purgeAudit().catch(() => {}), 6 * 3_600_000).unref();
  setInterval(() => pushDue().catch((e) => console.error("[audit-export] job", (e as Error).message)), 15 * 60_000).unref();
  setInterval(() => purgePlatformAudit().catch(() => {}), 6 * 3_600_000).unref();
  setInterval(() => purgeRetiredKeys().catch(() => {}), 6 * 3_600_000).unref();
}
