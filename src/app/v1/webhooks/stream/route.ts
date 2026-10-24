import { handler, errors, ApiError } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { rateLimit } from "@/lib/cache";
import { record } from "@/lib/audit";
import { EVENT_TYPES } from "@/lib/webhooks";
import { openStream } from "@/lib/webhook-stream";

export const dynamic = "force-dynamic";

/**
 * Server-sent events for `daywalker listen`. Development instances only: a production instance's
 * events (real user data) are never streamed to a developer's machine. Authenticated with the secret
 * key in the Authorization header (never the URL, so it can't end up in logs).
 */
export const GET = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  if (inst.environment !== "development") throw new ApiError(403, "development_only", "The event stream is only available on development instances");
  if ((await rateLimit(`${inst.id}:webhook_stream`, 120, 3600)) < 0) throw errors.tooMany();
  const q = new URL(req.url).searchParams.get("events");
  let types: string[] | null = null;
  if (q && q !== "*") {
    types = [...new Set(q.split(",").map((s) => s.trim()).filter(Boolean))];
    const bad = types.find((t) => !(EVENT_TYPES as readonly string[]).includes(t));
    if (bad || types.length > 50) throw errors.badRequest("invalid_event", `Unknown event type "${bad ?? ""}"`);
  }
  const res = await openStream(inst.id, req.signal, types);
  if (!res) throw new ApiError(429, "too_many_streams", "This instance already has the maximum number of listeners connected");
  void record(inst.id, "webhook.stream_connected", { actor: { type: "api" } });
  return res;
});
