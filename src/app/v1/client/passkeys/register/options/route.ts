import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireFreshSession } from "@/lib/auth/require-session";
import { registrationOptions } from "@/lib/auth/passkeys";

export const OPTIONS = preflight;

/** Step 1 of adding a passkey. Requires a session that started in the last 15 minutes. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireFreshSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("passkey_reg", 20, 900);
  return ctx.json(await registrationOptions(ctx.inst, s.userId, s.id));
});
