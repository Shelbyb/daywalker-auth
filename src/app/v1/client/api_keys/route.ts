import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireFreshSession, requireSession } from "@/lib/auth/require-session";
import { createForSession, listForSession } from "@/lib/auth/api-keys";
import { errors } from "@/lib/http";
import { rateLimit } from "@/lib/cache";

export const OPTIONS = preflight;

/** The signed-in user's API keys, or an organization's with ?orgId= (needs org:manage). */
export const GET = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  return ctx.json({ data: await listForSession(ctx.inst, s.userId, new URL(req.url).searchParams.get("orgId") ?? undefined) });
});

/** Creates a key (shown once). Needs a recently started session, and isn't allowed while impersonating. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireFreshSession(ctx.inst, ctx.refreshToken);
  if (s.impersonatorId) throw errors.forbidden("Not available while impersonating").withCode("impersonation_forbidden");
  if ((await rateLimit(`${ctx.inst.id}:apikey_create:${s.userId}`, 20, 3600)) < 0) throw errors.tooMany();
  return ctx.json(await createForSession(ctx.inst, s.userId, await req.json()), { status: 201 });
});
