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
export function handler<A extends unknown[]>(fn: (...args: A) => Promise<Response>) {
  return async (...args: A): Promise<Response> => {
    try {
      return await fn(...args);
    } catch (e) {
      if (e instanceof ApiError)
        return NextResponse.json({ error: { code: e.code, message: e.message } }, { status: e.status });
      if (e instanceof ZodError)
        return NextResponse.json(
          { error: { code: "invalid_request", message: "Invalid request", fields: e.issues.map((i) => ({ path: i.path.join("."), message: i.message })) } },
          { status: 422 },
        );
      console.error(e);
      return NextResponse.json({ error: { code: "internal_error", message: "Something went wrong" } }, { status: 500 });
    }
  };
}

export function clientIp(req: Request) {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || req.headers.get("x-real-ip") || "unknown";
}
