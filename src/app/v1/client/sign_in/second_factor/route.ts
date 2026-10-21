import { z } from "zod";
import { handler, clientIp } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { completePendingSecondFactor } from "@/lib/auth/mfa";
import { createSession, issueToken } from "@/lib/auth/sessions";
import { getUser } from "@/lib/auth/users";

export const OPTIONS = preflight;

/** Finish sign-in with a 6-digit authenticator code or a backup code. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("second_factor", 30, 900);
  const { code } = z.object({ code: z.string().trim().min(6).max(20) }).parse(await req.json());
  const userId = await completePendingSecondFactor(ctx.inst.id, ctx.twoFactorToken, code);
  const s = await createSession(ctx.inst, userId, { userAgent: req.headers.get("user-agent"), ip: clientIp(req) });
  const { jwt } = await issueToken(ctx.inst, s.refreshToken, ctx.origin);
  const res = ctx.clearTwoFactorCookie(ctx.json({ status: "complete", user: await getUser(ctx.inst.id, userId), sessionId: s.id, jwt }));
  return ctx.setRefreshCookie(res, s.refreshToken, s.expiresAt);
});
