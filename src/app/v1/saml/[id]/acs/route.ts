import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { ApiError } from "@/lib/http";
import { completeSso, STATE_COOKIE, takeState } from "@/lib/auth/saml";
import { getInstance, publishableKey } from "@/lib/auth/instance";
import { finishRedirectSignIn } from "@/lib/auth/finish-redirect";
import { env } from "@/lib/env";

const SAFE_ERRORS = new Set(["oauth_failed", "email_unverified", "forbidden", "legal_required", "sso_not_configured"]);
const clear = (res: NextResponse) => res.cookies.set(STATE_COOKIE, "", { path: "/v1/saml", maxAge: 0 });

/** Assertion consumer service: the identity provider posts the signed response here. */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const fail = (status: number, msg: string) => {
    const res = new NextResponse(msg, { status, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
    clear(res);
    return res;
  };
  if (Number(req.headers.get("content-length") ?? 0) > 512 * 1024) return fail(413, "Response too large");
  const form = await req.formData().catch(() => null);
  const samlResponse = form?.get("SAMLResponse");
  const relayState = form?.get("RelayState");
  if (typeof samlResponse !== "string" || typeof relayState !== "string") return fail(400, "Missing SAML response");

  // Only responses to a sign-in started in this browser: IdP-initiated and replayed responses stop here.
  const pending = await takeState(id, relayState, (await cookies()).get(STATE_COOKIE)?.value);
  if (!pending) return fail(400, "This sign-in has expired or was started in a different browser. Please try again.");
  const inst = await getInstance(pending.instanceId);
  if (!inst) return fail(400, "Unknown app");

  const back = (code: string) => {
    const to = new URL(`${env().APP_URL}/sign-in`);
    to.searchParams.set("pk", publishableKey(inst));
    to.searchParams.set("error", SAFE_ERRORS.has(code) ? code : "oauth_failed");
    if (pending.redirect) to.searchParams.set("redirect_url", pending.redirect);
    const res = NextResponse.redirect(to, 302);
    clear(res);
    return res;
  };
  try {
    const userId = await completeSso(inst, id, pending, samlResponse);
    return await finishRedirectSignIn(req, inst, userId, pending.redirect, "saml", clear);
  } catch (e) {
    if (e instanceof ApiError) return back(e.code);
    console.error("SAML sign-in failed", (e as Error).message);
    return back("oauth_failed");
  }
}
