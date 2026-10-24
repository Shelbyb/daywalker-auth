import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { cloneConfig } from "@/lib/auth/application";
import { rateLimit } from "@/lib/cache";
import { errors } from "@/lib/http";

/**
 * Backend API, called with the PRODUCTION instance's secret key: copies configuration from the application's
 * development instance into it. Users and keys are never copied; secrets only when listed in `copySecrets`.
 */
export const POST = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  if ((await rateLimit(`${inst.id}:clone`, 10, 3600)) < 0) throw errors.tooMany();
  const body = await req.json().catch(() => ({}));
  return NextResponse.json(await cloneConfig(inst, body, { type: "api" }));
});
