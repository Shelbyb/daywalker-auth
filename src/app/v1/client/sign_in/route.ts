import { handler, clientIp } from "@/lib/http";
import { frontendContext, preflight, setTwoFactorCookie } from "@/lib/auth/frontend";
import { signIn, signInInput, getUser } from "@/lib/auth/users";
import { createSession, issueTokenOrSetup } from "@/lib/auth/sessions";
import { hasTwoFactor, createPendingSecondFactor } from "@/lib/auth/mfa";
import { assertHuman } from "@/lib/auth/signup-protection";

export const OPTIONS = preflight;

export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const input = signInInput.parse(await req.json());
  // Per-IP and per-account limits: stops both spraying and targeted guessing.
  await ctx.limit("sign_in", 20, 300);
  await ctx.limit("sign_in_acct", 10, 900, input.email);
  await assertHuman(ctx.inst, input.captchaToken, clientIp(req), "login");
  const userId = await signIn(ctx.inst, input);

  // Password was right, but the account needs a second factor: no session yet.
  if (await hasTwoFactor(userId)) {
    const { token, maxAge } = await createPendingSecondFactor(ctx.inst.id, userId);
    return setTwoFactorCookie(ctx.json({ status: "needs_second_factor" }), ctx.inst.id, token, maxAge);
  }

  const s = await createSession(ctx.inst, userId, { userAgent: req.headers.get("user-agent"), ip: clientIp(req) });
  const { jwt, twoFactorSetupRequired } = await issueTokenOrSetup(ctx.inst, s.refreshToken, ctx.origin);
  const res = ctx.json({ status: "complete", user: await getUser(ctx.inst.id, userId), sessionId: s.id, jwt, ...(twoFactorSetupRequired ? { twoFactorSetupRequired } : {}) });
  return ctx.setRefreshCookie(res, s.refreshToken, s.expiresAt);
});
