import { z } from "zod";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { handler, clientIp } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { completePasskeySignUp } from "@/lib/auth/passkey-signup";
import { readCredential } from "@/lib/auth/webauthn-input";
import { createSession, issueTokenOrSetup } from "@/lib/auth/sessions";
import { getUser } from "@/lib/auth/users";

export const OPTIONS = preflight;

/**
 * Step 3: the browser's attestation. Creates the account and signs it in. A user-verified passkey counts
 * as two factors, and the email is already verified, so nothing else follows.
 */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("passkey_signup_complete", 20, 3600);
  const body = await readCredential<RegistrationResponseJSON>(req, { token: z.string().min(20).max(100), name: z.string().max(60).optional() });
  const userId = await completePasskeySignUp(ctx.inst, body.token as string, body.response, body.name as string | undefined);
  const s = await createSession(ctx.inst, userId, { userAgent: req.headers.get("user-agent"), ip: clientIp(req), secondFactor: true });
  const { jwt, twoFactorSetupRequired } = await issueTokenOrSetup(ctx.inst, s.refreshToken, ctx.origin);
  const res = ctx.json({ user: await getUser(ctx.inst.id, userId), sessionId: s.id, jwt, ...(twoFactorSetupRequired ? { twoFactorSetupRequired } : {}) }, { status: 201 });
  return ctx.setRefreshCookie(res, s.refreshToken, s.expiresAt);
});
