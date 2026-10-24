import { NextResponse } from "next/server";
import { z } from "zod";
import { handler, errors } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { verifyKey } from "@/lib/auth/api-keys";
import { rateLimit } from "@/lib/cache";

/** Backend API: is this API key valid for your app? `{ valid: false }` for anything wrong, without saying why. */
export const POST = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  if ((await rateLimit(`${inst.id}:apikey_verify`, 6000, 60)) < 0) throw errors.tooMany();
  const { key } = z.object({ key: z.string().max(300) }).strict().parse(await req.json());
  return NextResponse.json(await verifyKey(inst, key), { headers: { "cache-control": "no-store" } });
});
