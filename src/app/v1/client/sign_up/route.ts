import { handler, clientIp } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { signUp, signUpInput, getUser } from "@/lib/auth/users";
import { createSession, issueToken } from "@/lib/auth/sessions";

export const OPTIONS = preflight;

export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("sign_up", 10, 3600);
  const input = signUpInput.parse(await req.json());
  const userId = await signUp(ctx.inst, input);
  const s = await createSession(ctx.inst, userId, { userAgent: req.headers.get("user-agent"), ip: clientIp(req) });
  const { jwt } = await issueToken(ctx.inst, s.refreshToken, ctx.origin);
  const res = ctx.json({ user: await getUser(ctx.inst.id, userId), sessionId: s.id, jwt }, { status: 201 });
  return ctx.setRefreshCookie(res, s.refreshToken, s.expiresAt);
});
