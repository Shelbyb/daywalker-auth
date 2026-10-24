import { NextResponse } from "next/server";
import { z } from "zod";
import { clientIp, handler } from "@/lib/http";
import { instanceFromPublishableKey } from "@/lib/auth/instance";
import { exchangeCode } from "@/lib/auth/satellites";

/**
 * Satellite session sync, step 3. Called by the satellite's server (no cookies, no CORS): trades the one-time
 * code plus the verifier it kept for the short-lived token. The code works once and only with its verifier.
 */
export const POST = handler(async (req: Request) => {
  const inst = await instanceFromPublishableKey(req);
  const input = z.object({ code: z.string().max(200), verifier: z.string().max(200) }).strict().parse(await req.json());
  const r = await exchangeCode(inst, input, clientIp(req));
  return NextResponse.json({ jwt: r.jwt }, { headers: { "cache-control": "no-store" } });
});
