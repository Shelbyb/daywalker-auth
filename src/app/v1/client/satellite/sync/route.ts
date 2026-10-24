import { NextResponse } from "next/server";
import { clientIp, handler } from "@/lib/http";
import { frontendContext } from "@/lib/auth/frontend";
import { startSync } from "@/lib/auth/satellites";

/**
 * Satellite session sync, step 2 (see auth/satellites.ts). A top-level navigation from a satellite domain:
 * reads this service's own refresh cookie and redirects back to the satellite with a one-time code (or signed_out).
 * Query: pk, return (the satellite's origin), challenge, to (where the satellite sends the person afterwards), primary.
 */
export const GET = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const q = new URL(req.url).searchParams;
  const dest = await startSync(ctx.inst, ctx.refreshToken, { returnOrigin: q.get("return"), to: q.get("to"), challenge: q.get("challenge"), primary: q.get("primary") }, clientIp(req));
  const res = NextResponse.redirect(dest, 302);
  res.headers.set("cache-control", "no-store");
  return res;
});
