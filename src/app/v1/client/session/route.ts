import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { resolveSession, endSession } from "@/lib/auth/sessions";
import { getUser } from "@/lib/auth/users";

export const OPTIONS = preflight;

/** Current session + user, or { session: null }. */
export const GET = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = ctx.refreshToken ? await resolveSession(ctx.inst.id, ctx.refreshToken) : null;
  if (!s) return ctx.json({ session: null, user: null });
  return ctx.json({ session: { id: s.id, expiresAt: s.expiresAt }, user: await getUser(ctx.inst.id, s.userId) });
});

/** Sign out. */
export const DELETE = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  if (ctx.refreshToken) await endSession(ctx.inst.id, ctx.refreshToken);
  return ctx.clearRefreshCookie(ctx.json({ ok: true }));
});
