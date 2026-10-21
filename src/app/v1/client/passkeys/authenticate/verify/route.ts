import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { handler, clientIp } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { verifyAuthentication } from "@/lib/auth/passkeys";
import { readCredential } from "@/lib/auth/webauthn-input";
import { createSession, issueToken } from "@/lib/auth/sessions";
import { getUser } from "@/lib/auth/users";

export const OPTIONS = preflight;

/**
 * Step 2: verify the signed assertion and start a session. A user-verified passkey is
 * already two factors (the device, plus biometric/PIN), so no TOTP step follows.
 */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("passkey_auth", 30, 300);
  const body = await readCredential<AuthenticationResponseJSON>(req);
  const userId = await verifyAuthentication(ctx.inst, body.response);
  const s = await createSession(ctx.inst, userId, { userAgent: req.headers.get("user-agent"), ip: clientIp(req) });
  const { jwt } = await issueToken(ctx.inst, s.refreshToken, ctx.origin);
  const res = ctx.json({ status: "complete", user: await getUser(ctx.inst.id, userId), sessionId: s.id, jwt });
  return ctx.setRefreshCookie(res, s.refreshToken, s.expiresAt);
});
