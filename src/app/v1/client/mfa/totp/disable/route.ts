import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { disableTwoFactor } from "@/lib/auth/mfa";

export const OPTIONS = preflight;

/** Turn 2FA off. Requires a current authenticator or backup code. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("mfa_disable", 10, 900);
  const { code } = z.object({ code: z.string().trim().max(20).optional() }).parse(await req.json());
  await disableTwoFactor(s.userId, code, s.id);
  return ctx.json({ enabled: false });
});
