import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { issueToken } from "@/lib/auth/sessions";

export const OPTIONS = preflight;

/** Exchange the refresh cookie for a fresh short-lived JWT. Clients call this before expiry. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("token", 120, 60);
  const { jwt, sessionId, userId } = await issueToken(ctx.inst, ctx.refreshToken, ctx.origin);
  return ctx.json({ jwt, sessionId, userId });
});
