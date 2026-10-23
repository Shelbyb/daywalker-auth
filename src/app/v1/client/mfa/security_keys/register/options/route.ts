import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireFreshSession } from "@/lib/auth/require-session";
import { startSecurityKeyEnrollment } from "@/lib/auth/mfa";

export const OPTIONS = preflight;

/** Step 1 of adding a security key. Needs a recent sign-in, and a current code if two-factor is already on. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireFreshSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("security_key_reg", 20, 900);
  const { code } = z.object({ code: z.string().trim().max(20).optional() }).parse(await req.json().catch(() => ({})));
  return ctx.json(await startSecurityKeyEnrollment(ctx.inst, s.userId, s.id, code));
});
