import { NextResponse } from "next/server";
import { handler, errors } from "@/lib/http";
import { instanceFromPublishableKey } from "@/lib/auth/instance";
import { isProvider, startOAuth, STATE_COOKIE } from "@/lib/auth/oauth";
import { safeRedirect } from "@/lib/auth/redirect";
import { env } from "@/lib/env";

/** Top-level navigation: GET /v1/client/oauth/google/start?pk=…&redirect_url=… → provider consent screen. */
export const GET = handler(async (req: Request, { params }: { params: Promise<{ provider: string }> }) => {
  const { provider } = await params;
  if (!isProvider(provider)) throw errors.notFound("Unknown provider");
  const inst = await instanceFromPublishableKey(req);
  const redirect = safeRedirect(new URL(req.url).searchParams.get("redirect_url") ?? undefined, inst.allowedOrigins);
  const legalAccepted = new URL(req.url).searchParams.get("legal_accepted") === "1";
  const { url, state, maxAge, formPost } = await startOAuth(inst, provider, redirect, legalAccepted);
  const secure = env().APP_URL.startsWith("https://");

  const res = NextResponse.redirect(url, 302);
  res.cookies.set(STATE_COOKIE, state, {
    httpOnly: true,
    secure,
    // Must come back with the provider's redirect. Apple returns with a cross-site POST, which
    // only carries SameSite=None cookies; the state check still blocks login CSRF.
    sameSite: formPost && secure ? "none" : "lax",
    path: "/v1/oauth",
    maxAge,
  });
  return res;
});
