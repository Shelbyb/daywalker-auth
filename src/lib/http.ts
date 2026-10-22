import { NextResponse } from "next/server";
import { ZodError } from "zod";

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
  /** Same status and message, more specific machine-readable code. */
  withCode(code: string) {
    this.code = code;
    return this;
  }
}

export const errors = {
  badRequest: (code: string, msg: string) => new ApiError(400, code, msg),
  unauthorized: (msg = "Not signed in") => new ApiError(401, "unauthenticated", msg),
  forbidden: (msg = "Forbidden") => new ApiError(403, "forbidden", msg),
  notFound: (msg = "Not found") => new ApiError(404, "not_found", msg),
  conflict: (code: string, msg: string) => new ApiError(409, code, msg),
  tooMany: () => new ApiError(429, "rate_limited", "Too many attempts. Try again shortly."),
};

/** Wrap a route handler: consistent JSON errors, never leak internals. */
/**
 * CORS headers granted to a request (set by the frontend API once the origin is checked), so
 * error responses carry them too. Without them a browser hides the error and the user sees
 * "network error" instead of "Email or password is incorrect".
 */
export const corsHeadersFor = new WeakMap<Request, Record<string, string>>();

export function handler<A extends unknown[]>(fn: (...args: A) => Promise<Response>) {
  return async (...args: A): Promise<Response> => {
    try {
      return await fn(...args);
    } catch (e) {
      const headers = args[0] instanceof Request ? (corsHeadersFor.get(args[0]) ?? {}) : {};
      if (e instanceof ApiError)
        return NextResponse.json({ error: { code: e.code, message: e.message } }, { status: e.status, headers });
      if (e instanceof ZodError)
        return NextResponse.json(
          { error: { code: "invalid_request", message: "Invalid request", fields: e.issues.map((i) => ({ path: i.path.join("."), message: i.message })) } },
          { status: 422, headers },
        );
      console.error(e);
      return NextResponse.json({ error: { code: "internal_error", message: "Something went wrong" } }, { status: 500, headers });
    }
  };
}

/**
 * Client IP for rate limiting. In production we sit behind TRUST_PROXY_HOPS proxies (default 1, e.g. DigitalOcean
 * App Platform). Each proxy appends the address it saw to X-Forwarded-For, so the real client is the Nth entry from
 * the RIGHT; anything to its left is client-supplied and spoofable, so it is ignored. Outside production the
 * leftmost entry is used (tests and local dev send their own header).
 */
export function clientIp(req: Request) {
  const xff = req.headers.get("x-forwarded-for");
  const parts = xff ? xff.split(",").map((p) => p.trim()).filter(Boolean) : [];
  if (process.env.NODE_ENV !== "production") return parts[0] || req.headers.get("x-real-ip") || "unknown";
  const raw = process.env.TRUST_PROXY_HOPS;
  const hops = raw !== undefined && raw !== "" && Number.isInteger(Number(raw)) && Number(raw) >= 0 ? Number(raw) : 1;
  if (hops === 0 || parts.length === 0) return "unknown"; // no trusted proxy: never believe forwarding headers
  return parts[Math.max(0, parts.length - hops)] || "unknown";
}
