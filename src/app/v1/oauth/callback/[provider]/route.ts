import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { clientIp, ApiError } from "@/lib/http";
import { isProvider, takeState, completeOAuth, STATE_COOKIE } from "@/lib/auth/oauth";
import { createSession } from "@/lib/auth/sessions";
import { setRefreshCookie } from "@/lib/auth/frontend";
import { publishableKey } from "@/lib/auth/instance";
import { env } from "@/lib/env";

// Only these codes ever reach the URL; the sign-in page maps them to fixed messages.
const SAFE_ERRORS = new Set(["oauth_cancelled", "oauth_failed", "email_unverified", "provider_disabled", "forbidden"]);

/** Provider redirects here with ?code&state. Always ends in a redirect, never a raw error page. */
export async function GET(req: Request, { params }: { params: Promise<{ provider: string }> }) {
  const { provider } = await params;
  const url = new URL(req.url);
  const jar = await cookies();
  const base = env().APP_URL;

  const fail = (status: number, msg: string) => {
    const res = new NextResponse(msg, { status, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
    res.cookies.set(STATE_COOKIE, "", { path: "/v1/oauth", maxAge: 0 });
    return res;
  };
  if (!isProvider(provider)) return fail(404, "Unknown provider");

  const pending = await takeState(provider, url.searchParams.get("state"), jar.get(STATE_COOKIE)?.value);
  // No valid state: expired, replayed, or started in a different browser. Never sign anyone in.
  if (!pending) return fail(400, "This sign-in link has expired or was opened in a different browser. Please try again.");

  const pk = publishableKey(pending.inst);
  const back = (code: string) => {
    const to = new URL(`${base}/sign-in`);
    to.searchParams.set("pk", pk);
    to.searchParams.set("error", SAFE_ERRORS.has(code) ? code : "oauth_failed");
    if (pending.redirect) to.searchParams.set("redirect_url", pending.redirect);
    const res = NextResponse.redirect(to, 302);
    res.cookies.set(STATE_COOKIE, "", { path: "/v1/oauth", maxAge: 0 });
    return res;
  };

  if (url.searchParams.get("error")) return back("oauth_cancelled"); // user clicked "Cancel" at the provider
  const code = url.searchParams.get("code");
  if (!code || code.length > 2048) return back("oauth_failed");

  try {
    const userId = await completeOAuth(pending.inst, provider, code, pending.verifier);
    const s = await createSession(pending.inst, userId, { userAgent: req.headers.get("user-agent"), ip: clientIp(req) });
    const dest = pending.redirect
      ? new URL(pending.redirect, base)
      : new URL(`${base}/sign-in?pk=${encodeURIComponent(pk)}&status=signed_in`);
    const res = NextResponse.redirect(dest, 302);
    res.cookies.set(STATE_COOKIE, "", { path: "/v1/oauth", maxAge: 0 });
    return setRefreshCookie(res, pending.inst.id, s.refreshToken, s.expiresAt);
  } catch (e) {
    if (e instanceof ApiError) return back(e.code);
    console.error("OAuth callback failed", e);
    return back("oauth_failed");
  }
}
