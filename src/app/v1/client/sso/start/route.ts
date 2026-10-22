import { NextResponse } from "next/server";
import { z } from "zod";
import { handler, clientIp, errors } from "@/lib/http";
import { instanceFromPublishableKey } from "@/lib/auth/instance";
import { safeRedirect } from "@/lib/auth/redirect";
import { STATE_COOKIE, startSso } from "@/lib/auth/saml";
import { rateLimit } from "@/lib/cache";
import { blindIndex } from "@/lib/crypto";
import { env } from "@/lib/env";

/** Top-level navigation: GET /v1/client/sso/start?pk=…&email=…&redirect_url=… → the company's sign-in page. */
export const GET = handler(async (req: Request) => {
  const inst = await instanceFromPublishableKey(req);
  if ((await rateLimit(`${inst.id}:sso_start:${blindIndex(clientIp(req), "ratelimit")}`, 30, 300)) < 0) throw errors.tooMany();
  const q = new URL(req.url).searchParams;
  const email = z.string().trim().toLowerCase().email().max(254).parse(q.get("email"));
  const redirect = safeRedirect(q.get("redirect_url") ?? undefined, inst.allowedOrigins);
  const { url, state, maxAge } = await startSso(inst, email, redirect, q.get("legal_accepted") === "1");
  const res = NextResponse.redirect(url, 302);
  const secure = env().APP_URL.startsWith("https://");
  // The identity provider returns with a cross-site POST, which only carries SameSite=None cookies.
  res.cookies.set(STATE_COOKIE, state, { httpOnly: true, secure, sameSite: secure ? "none" : "lax", path: "/v1/saml", maxAge });
  return res;
});
