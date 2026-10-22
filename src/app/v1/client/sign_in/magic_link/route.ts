import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { linkInput, useMagicLink } from "@/lib/auth/email-sign-in";
import { completeFirstFactor } from "@/lib/auth/complete-sign-in";

export const OPTIONS = preflight;

/** Exchanges a one-time link token for a session. Returns where the user asked to go, if anywhere. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const input = linkInput.parse(await req.json());
  await ctx.limit("esi_link", 30, 900);
  const r = await useMagicLink(ctx.inst, input.token);
  return completeFirstFactor(req, ctx, r.userId, r.method, { redirectUrl: r.redirect });
});
