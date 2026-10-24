import { NextResponse, type NextRequest } from "next/server";

const prod = process.env.NODE_ENV === "production";

/**
 * Pages that handle credentials, tokens or user data: scripts only run if they carry this
 * request's random nonce, so injected markup can't execute even if it slips past escaping.
 * These pages render per request anyway (they read search params and cookies).
 */
const STRICT = /^\/(sign-in|sign-up|forgot-password|second-factor|magic-link|accept-invite|unauthorized-sign-in|account|organization|create-organization|dashboard)(\/|$)/;

function policy(nonce: string | null) {
  const script = nonce
    ? `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${prod ? "" : " 'unsafe-eval'"}`
    : // Docs and the home page are static and contain no user input, so they keep static rendering.
      `script-src 'self' 'unsafe-inline'${prod ? "" : " 'unsafe-eval'"}`;
  return [
    "default-src 'self'",
    script,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "connect-src 'self'",
    "font-src 'self'",
    "frame-src https://challenges.cloudflare.com", // the optional Turnstile human check
    "frame-ancestors 'none'", // hosted pages must never be framed (clickjacking)
    "form-action 'self'",
    "base-uri 'none'",
    "object-src 'none'",
  ].join("; ");
}

/** Default hosted-page URL: /h/<publishable key>/<page>, unique per instance and needing no subdomain. */
const HOSTED = /^\/h\/(pk_(?:test|live)_[A-Za-z0-9_-]+)(\/(?:sign-in|sign-up|forgot-password|unauthorized-sign-in|account|organization|create-organization)(?:\/.*)?)?$/;

export function proxy(req: NextRequest) {
  const hosted = HOSTED.exec(req.nextUrl.pathname);
  const url = req.nextUrl.clone();
  if (hosted) {
    url.pathname = hosted[2] ?? "/sign-in";
    url.searchParams.set("pk", hosted[1]);
  }
  const strict = STRICT.test(url.pathname);
  const nonce = strict ? btoa(crypto.randomUUID()) : null;
  const csp = policy(nonce);

  // Next reads the nonce from the request's CSP header and stamps its own scripts with it.
  const headers = new Headers(req.headers);
  headers.set("content-security-policy", csp);
  if (nonce) headers.set("x-nonce", nonce);
  // Always overwritten here, so a client-supplied value is never seen. Lets layouts know where to return to after a session refresh.
  headers.set("x-dw-path", url.pathname);
  headers.set("x-dw-search", url.search);

  const res = hosted ? NextResponse.rewrite(url, { request: { headers } }) : NextResponse.next({ request: { headers } });
  res.headers.set("Content-Security-Policy", csp);
  return res;
}

// Pages only: skip API routes, JWKS, health checks and static assets.
export const config = {
  matcher: [{ source: "/((?!v1/|i/|healthz|_next/static|_next/image|favicon.ico).*)", missing: [{ type: "header", key: "next-router-prefetch" }] }],
};
