import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { revokeOtherSessions } from "@/lib/auth/account";

export const OPTIONS = preflight;

/** "Sign out everywhere else." */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  return ctx.json({ signedOut: await revokeOtherSessions(s.userId, s.id) });
});
