import { clientIp } from "../http";
import { createSession, issueToken } from "./sessions";
import { createPendingSecondFactor, hasTwoFactor } from "./mfa";
import { getUser } from "./users";
import { setTwoFactorCookie, type frontendContext } from "./frontend";

type Ctx = Awaited<ReturnType<typeof frontendContext>>;

/** Shared tail of every first-factor sign-in: ask for 2FA if it's on, otherwise start a session. */
export async function completeFirstFactor(req: Request, ctx: Ctx, userId: string, method: string, extra: Record<string, unknown> = {}) {
  if (await hasTwoFactor(userId)) {
    const { token, maxAge } = await createPendingSecondFactor(ctx.inst.id, userId);
    return setTwoFactorCookie(ctx.json({ status: "needs_second_factor", ...extra }), ctx.inst.id, token, maxAge);
  }
  const s = await createSession(ctx.inst, userId, { userAgent: req.headers.get("user-agent"), ip: clientIp(req), method });
  const { jwt } = await issueToken(ctx.inst, s.refreshToken, ctx.origin);
  const res = ctx.json({ status: "complete", user: await getUser(ctx.inst.id, userId), sessionId: s.id, jwt, ...extra });
  return ctx.setRefreshCookie(res, s.refreshToken, s.expiresAt);
}
