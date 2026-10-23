import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { startKeyConfirmation } from "@/lib/auth/mfa";

export const OPTIONS = preflight;

/** Step 1 of confirming a sensitive change with a security key instead of a code. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("security_key_confirm", 20, 900);
  return ctx.json(await startKeyConfirmation(s.userId));
});
