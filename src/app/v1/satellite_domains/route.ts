import { NextResponse } from "next/server";
import { z } from "zod";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { addSatellite, listSatellites } from "@/lib/auth/satellites";

/** Backend API: satellite domains (other domains of the same app that share sessions). */
export const GET = handler(async (req: Request) => NextResponse.json({ data: await listSatellites((await instanceFromSecretKey(req)).id) }));

/** Body: { domain }. Returns the DNS TXT record to publish before calling verify. */
export const POST = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  const { domain } = z.object({ domain: z.string().max(300) }).strict().parse(await req.json());
  return NextResponse.json(await addSatellite(inst, domain, { type: "api" }), { status: 201 });
});
