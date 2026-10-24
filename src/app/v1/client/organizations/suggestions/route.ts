import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { suggestionsFor } from "@/lib/auth/org-domains";

export const OPTIONS = preflight;

/** Organizations offered because a VERIFIED email of the signed-in person is at an organization's verified domain. */
export const GET = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  return ctx.json({ suggestions: await suggestionsFor(ctx.inst, s.userId) });
});
