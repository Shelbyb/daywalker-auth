import { NextResponse } from "next/server";
import { z } from "zod";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { primaryDomainOf, setPrimaryDomain } from "@/lib/auth/satellites";

/** Backend API: the application's primary domain (an origin), which is also an allowed origin. */
export const GET = handler(async (req: Request) => NextResponse.json({ primaryDomain: primaryDomainOf(await instanceFromSecretKey(req)) }));

export const PUT = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  const { primaryDomain } = z.object({ primaryDomain: z.string().max(300).nullable() }).strict().parse(await req.json());
  return NextResponse.json(await setPrimaryDomain(inst, primaryDomain, { type: "api" }));
});
