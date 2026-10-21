import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { listSessions } from "@/lib/auth/account";

export const OPTIONS = preflight;

/** The signed-in user's active sessions (device, approximate IP, last active). */
export const GET = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  return ctx.json({ sessions: await listSessions(ctx.inst.id, s.userId, s.id) });
});
