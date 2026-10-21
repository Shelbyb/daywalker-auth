import { handler, clientIp } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { signIn, signInInput, getUser } from "@/lib/auth/users";
import { createSession, issueToken } from "@/lib/auth/sessions";

export const OPTIONS = preflight;

export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const input = signInInput.parse(await req.json());
  // Per-IP and per-account limits: stops both spraying and targeted guessing.
  await ctx.limit("sign_in", 20, 300);
  await ctx.limit("sign_in_acct", 10, 900, input.email);
  const userId = await signIn(ctx.inst, input);
  const s = await createSession(ctx.inst, userId, { userAgent: req.headers.get("user-agent"), ip: clientIp(req) });
  const { jwt } = await issueToken(ctx.inst, s.refreshToken, ctx.origin);
  const res = ctx.json({ user: await getUser(ctx.inst.id, userId), sessionId: s.id, jwt });
  return ctx.setRefreshCookie(res, s.refreshToken, s.expiresAt);
});
