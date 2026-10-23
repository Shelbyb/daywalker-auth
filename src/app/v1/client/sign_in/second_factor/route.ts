import { z } from "zod";
import { handler, clientIp } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { completePendingSecondFactor, completePendingWithSecurityKey } from "@/lib/auth/mfa";
import { readCredential } from "@/lib/auth/webauthn-input";
import { createSession, issueTokenOrSetup } from "@/lib/auth/sessions";
import { getUser } from "@/lib/auth/users";
import { linkAfterSecondFactor } from "@/lib/auth/saml-logout";

export const OPTIONS = preflight;

/** Finish sign-in with a 6-digit authenticator code, a texted code, a backup code, or a security key's answer. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("second_factor", 30, 900);
  const raw = await req.clone().json().catch(() => null);
  let userId: string;
  if (raw && typeof raw === "object" && "response" in raw) {
    const body = await readCredential<AuthenticationResponseJSON>(req);
    userId = await completePendingWithSecurityKey(ctx.inst, ctx.twoFactorToken, body.response);
  } else {
    const { code, method } = z.object({ code: z.string().trim().min(6).max(20), method: z.enum(["totp", "sms"]).optional() }).parse(raw);
    userId = await completePendingSecondFactor(ctx.inst.id, ctx.twoFactorToken, code, method);
  }
  const s = await createSession(ctx.inst, userId, { userAgent: req.headers.get("user-agent"), ip: clientIp(req) });
  await linkAfterSecondFactor(ctx.twoFactorToken, s.id); // a SAML sign-in that needed 2FA
  const { jwt, twoFactorSetupRequired } = await issueTokenOrSetup(ctx.inst, s.refreshToken, ctx.origin);
  const res = ctx.clearTwoFactorCookie(ctx.json({ status: "complete", user: await getUser(ctx.inst.id, userId), sessionId: s.id, jwt, ...(twoFactorSetupRequired ? { twoFactorSetupRequired } : {}) }));
  return ctx.setRefreshCookie(res, s.refreshToken, s.expiresAt);
});
