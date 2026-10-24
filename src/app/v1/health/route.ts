import { getHealth } from "@/lib/health";
import { rateLimit } from "@/lib/cache";
import { clientIp, handler } from "@/lib/http";

export const dynamic = "force-dynamic";

/**
 * Public, unauthenticated service health: overall status plus ok/degraded/down per component and nothing else.
 * 200 when ok or degraded (still serving), 503 when down, so load balancers and uptime monitors can use the status code.
 */
export const GET = handler(async (req: Request) => {
  // Cheap abuse guard; if the cache itself is down, answer anyway (that is what this endpoint reports).
  const limited = await rateLimit(`health:${clientIp(req)}`, 120, 60).then((n) => n < 0, () => false);
  if (limited) return Response.json({ error: { code: "rate_limited", message: "Too many requests" } }, { status: 429, headers: { "Cache-Control": "no-store", "Retry-After": "30" } });
  const h = await getHealth();
  return Response.json(h, { status: h.status === "down" ? 503 : 200, headers: { "Cache-Control": "no-store" } });
});
