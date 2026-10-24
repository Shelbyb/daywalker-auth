import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { bindSession } from "@/lib/auth/sessions";

export const OPTIONS = preflight;

/**
 * Binds the current session to the device key proven by the `DPoP` header. For sign-ins that return
 * through a browser redirect (social, SSO, magic link) and so couldn't carry a proof: the SDK calls
 * this right after. Only within two minutes of sign-in, only once.
 */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("bind", 20, 60);
  const { sessionId } = await bindSession(ctx.inst, ctx.refreshToken);
  return ctx.json({ sessionId, deviceBound: true });
});
