import { NextResponse } from "next/server";
import { clientIp } from "../http";
import { env } from "../env";
import { createSession } from "./sessions";
import { setRefreshCookie, setTwoFactorCookie } from "./frontend";
import { hasTwoFactor, createPendingSecondFactor } from "./mfa";
import { publishableKey } from "./instance";
import type { Instance } from "../db/schema";

/**
 * Last step of a redirect-based sign-in (social or SSO): hand over to the hosted 2FA page if the
 * account has it, otherwise start a session and send the user where they asked to go.
 * `clearCookie` removes the flow's state cookie.
 */
export async function finishRedirectSignIn(
  req: Request,
  inst: Instance,
  userId: string,
  redirect: string | null,
  method: string,
  clearCookie: (res: NextResponse) => void,
  hooks: { onSession?: (sessionId: string) => Promise<void>; onPending?: (token: string) => Promise<void> } = {},
) {
  const base = env().APP_URL;
  const pk = publishableKey(inst);
  if (await hasTwoFactor(userId)) {
    // The provider counts as the first factor only; finish on the hosted 2FA page.
    const { token, maxAge } = await createPendingSecondFactor(inst.id, userId);
    await hooks.onPending?.(token);
    const to = new URL(`${base}/second-factor`);
    to.searchParams.set("pk", pk);
    if (redirect) to.searchParams.set("redirect_url", redirect);
    const res = NextResponse.redirect(to, 302);
    clearCookie(res);
    return setTwoFactorCookie(res, inst.id, token, maxAge);
  }
  const s = await createSession(inst, userId, { userAgent: req.headers.get("user-agent"), ip: clientIp(req), method, redirectFlow: true });
  await hooks.onSession?.(s.id);
  const dest = redirect ? new URL(redirect, base) : new URL(`${base}/sign-in?pk=${encodeURIComponent(pk)}&status=signed_in`);
  const res = NextResponse.redirect(dest, 302);
  clearCookie(res);
  return setRefreshCookie(res, inst.id, s.refreshToken, s.expiresAt);
}
