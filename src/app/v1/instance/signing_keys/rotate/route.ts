import { NextResponse } from "next/server";
import { handler, errors } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { rateLimit } from "@/lib/cache";
import { rotateSigningKey } from "@/lib/auth/keys";

/** Backend API: start signing with a new key. Nobody is signed out; the old key stays in the JWKS for a day. */
export const POST = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  if ((await rateLimit(`${inst.id}:rotate_key`, 5, 3600)) < 0) throw errors.tooMany();
  return NextResponse.json(await rotateSigningKey(inst.id), { status: 201 });
});
