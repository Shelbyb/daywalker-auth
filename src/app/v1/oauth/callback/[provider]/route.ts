import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { clientIp, ApiError } from "@/lib/http";
import { isProvider, takeState, completeOAuth, STATE_COOKIE } from "@/lib/auth/oauth";
import { createSession } from "@/lib/auth/sessions";
import { setRefreshCookie, setTwoFactorCookie } from "@/lib/auth/frontend";
import { hasTwoFactor, createPendingSecondFactor } from "@/lib/auth/mfa";
import { publishableKey } from "@/lib/auth/instance";
import { env } from "@/lib/env";
import { refusalReason, unauthorizedUrl } from "@/lib/auth/unauthorized";

// Only these codes ever reach the URL; the sign-in page maps them to fixed messages.
const SAFE_ERRORS = new Set(["oauth_cancelled", "oauth_failed", "email_unverified", "provider_disabled", "forbidden", "legal_required", "sso_required"]);

/** Most providers redirect here with ?code&state. */
export async function GET(req: Request, ctx: { params: Promise<{ provider: string }> }) {
  return handle(req, (await ctx.params).provider, new URL(req.url).searchParams);
}

/** Apple posts the same fields as a form (response_mode=form_post). Only Apple may use POST. */
export async function POST(req: Request, ctx: { params: Promise<{ provider: string }> }) {
  const { provider } = await ctx.params;
  if (provider !== "apple") return new NextResponse("Method not allowed", { status: 405 });
  const len = Number(req.headers.get("content-length") ?? 0);
  if (len > 16_384) return new NextResponse("Too large", { status: 413 });
  const form = await req.formData().catch(() => null);
  const params = new URLSearchParams();
  for (const k of ["code", "state", "error", "user"]) {
    const v = form?.get(k);
    if (typeof v === "string") params.set(k, v.slice(0, 4096));
  }
  return handle(req, provider, params);
}

/** Always ends in a redirect, never a raw error page. */
async function handle(req: Request, provider: string, q: URLSearchParams) {
  const jar = await cookies();
  const base = env().APP_URL;

  const fail = (status: number, msg: string) => {
    const res = new NextResponse(msg, { status, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
    res.cookies.set(STATE_COOKIE, "", { path: "/v1/oauth", maxAge: 0 });
    return res;
  };
  if (!isProvider(provider)) return fail(404, "Unknown provider");

  const pending = await takeState(provider, q.get("state"), jar.get(STATE_COOKIE)?.value);
  // No valid state: expired, replayed, or started in a different browser. Never sign anyone in.
  if (!pending) return fail(400, "This sign-in link has expired or was opened in a different browser. Please try again.");

  const pk = publishableKey(pending.inst);
  const back = (code: string) => {
    const to = new URL(`${base}/${code === "legal_required" ? "sign-up" : "sign-in"}`);
    to.searchParams.set("pk", pk);
    to.searchParams.set("error", SAFE_ERRORS.has(code) ? code : "oauth_failed");
    if (pending.redirect) to.searchParams.set("redirect_url", pending.redirect);
    const res = NextResponse.redirect(to, 302);
    res.cookies.set(STATE_COOKIE, "", { path: "/v1/oauth", maxAge: 0 });
    return res;
  };

  if (q.get("error")) return back("oauth_cancelled"); // user clicked "Cancel" at the provider
  const code = q.get("code");
  if (!code || code.length > 2048) return back("oauth_failed");

  try {
    const userId = await completeOAuth(pending.inst, provider, code, pending, q.get("user"));
    if (await hasTwoFactor(userId)) {
      // Provider sign-in counts as the first factor only; finish on the hosted 2FA page.
      const { token, maxAge } = await createPendingSecondFactor(pending.inst.id, userId);
      const to = new URL(`${base}/second-factor`);
      to.searchParams.set("pk", pk);
      if (pending.redirect) to.searchParams.set("redirect_url", pending.redirect);
      const res = NextResponse.redirect(to, 302);
      res.cookies.set(STATE_COOKIE, "", { path: "/v1/oauth", maxAge: 0 });
      return setTwoFactorCookie(res, pending.inst.id, token, maxAge);
    }
    const s = await createSession(pending.inst, userId, { userAgent: req.headers.get("user-agent"), ip: clientIp(req) });
    const dest = pending.redirect
      ? new URL(pending.redirect, base)
      : new URL(`${base}/sign-in?pk=${encodeURIComponent(pk)}&status=signed_in`);
    const res = NextResponse.redirect(dest, 302);
    res.cookies.set(STATE_COOKIE, "", { path: "/v1/oauth", maxAge: 0 });
    return setRefreshCookie(res, pending.inst.id, s.refreshToken, s.expiresAt);
  } catch (e) {
    if (e instanceof ApiError) {
      // The instance refused this person (suspended, sign-ups restricted): not something a retry fixes.
      const reason = refusalReason(e.code, e.message);
      if (reason) {
        const res = NextResponse.redirect(unauthorizedUrl(base, pk, reason, pending.redirect), 302);
        res.cookies.set(STATE_COOKIE, "", { path: "/v1/oauth", maxAge: 0 });
        return res;
      }
      return back(e.code);
    }
    console.error("OAuth callback failed", e);
    return back("oauth_failed");
  }
}
