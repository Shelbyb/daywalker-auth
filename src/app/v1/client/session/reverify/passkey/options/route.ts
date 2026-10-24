import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { passkeyReverifyOptions } from "@/lib/auth/stepup";

export const OPTIONS = preflight;

/** Step 1 of re-verifying with a passkey: only this person's passkeys can answer. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("reverify_passkey", 30, 900);
  return ctx.json(await passkeyReverifyOptions(ctx.inst, s));
});
