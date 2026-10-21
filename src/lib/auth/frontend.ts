import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { env } from "../env";
import { errors, clientIp } from "../http";
import { rateLimit } from "../cache";
import { blindIndex } from "../crypto";
import { instanceFromPublishableKey } from "./instance";
import { refreshCookieName } from "./sessions";
import { twoFactorCookieName } from "./mfa";
import type { Instance } from "../db/schema";

/** Pending second-factor cookie: same scope and flags as the refresh cookie, 5-minute life. */
export function setTwoFactorCookie(res: NextResponse, instanceId: string, token: string, maxAge: number) {
  const secure = env().APP_URL.startsWith("https://");
  res.cookies.set(twoFactorCookieName(instanceId), token, { httpOnly: true, secure, sameSite: secure ? "none" : "lax", path: "/v1/client", maxAge });
  return res;
}

/** Shared by the frontend API and the OAuth callback. */
export function setRefreshCookie(res: NextResponse, instanceId: string, token: string, expires: Date) {
  const secure = env().APP_URL.startsWith("https://");
  res.cookies.set(refreshCookieName(instanceId), token, {
    httpOnly: true,
    secure,
    // Cross-site apps need SameSite=None (requires HTTPS). Same-site dev uses Lax.
    sameSite: secure ? "none" : "lax",
    path: "/v1/client",
    expires,
  });
  return res;
}

/** Requests must come from this service's own origin or one the instance allows. */
function allowedOrigin(inst: Instance, origin: string | null) {
  if (!origin) return null;
  if (origin === new URL(env().APP_URL).origin) return origin;
  return inst.allowedOrigins.includes(origin) ? origin : null;
}

/**
 * Shared preamble for frontend API routes: resolve instance, enforce origin (CSRF guard
 * for cookie-authenticated mutations), and build CORS headers.
 */
export async function frontendContext(req: Request) {
  const inst = await instanceFromPublishableKey(req);
  const origin = req.headers.get("origin");
  const allowed = allowedOrigin(inst, origin);
  if (req.method !== "GET" && !allowed) throw errors.forbidden("Origin not allowed");
  const cors: Record<string, string> = allowed
    ? { "access-control-allow-origin": allowed, "access-control-allow-credentials": "true", vary: "Origin" }
    : {};
  const jar = await cookies();
  const name = refreshCookieName(inst.id);
  return {
    inst,
    origin: allowed ?? undefined,
    refreshToken: jar.get(name)?.value,
    twoFactorToken: jar.get(twoFactorCookieName(inst.id))?.value,
    clearTwoFactorCookie(res: NextResponse) {
      res.cookies.set(twoFactorCookieName(inst.id), "", { path: "/v1/client", maxAge: 0 });
      return res;
    },
    json(body: unknown, init: ResponseInit = {}) {
      return NextResponse.json(body, { ...init, headers: { ...cors, ...(init.headers as object) } });
    },
    setRefreshCookie(res: NextResponse, token: string, expires: Date) {
      return setRefreshCookie(res, inst.id, token, expires);
    },
    clearRefreshCookie(res: NextResponse) {
      res.cookies.set(name, "", { path: "/v1/client", maxAge: 0 });
      return res;
    },
    /** Keys are HMAC'd so Valkey never holds raw IPs or emails. */
    async limit(bucket: string, max: number, windowSeconds: number, subject = clientIp(req)) {
      const remaining = await rateLimit(`${inst.id}:${bucket}:${blindIndex(subject, "ratelimit")}`, max, windowSeconds);
      if (remaining < 0) throw errors.tooMany();
    },
  };
}

export async function preflight(req: Request) {
  const inst = await instanceFromPublishableKey(req).catch(() => null);
  const allowed = inst && allowedOrigin(inst, req.headers.get("origin"));
  return new Response(null, {
    status: 204,
    headers: allowed
      ? {
          "access-control-allow-origin": allowed,
          "access-control-allow-credentials": "true",
          "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
          "access-control-allow-headers": "content-type, x-publishable-key",
          "access-control-max-age": "600",
          vary: "Origin",
        }
      : {},
  });
}
