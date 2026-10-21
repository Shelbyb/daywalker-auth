import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { listSigningKeys } from "@/lib/auth/keys";

/** Backend API: the instance's signing keys (public details only). */
export const GET = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  return NextResponse.json({ data: await listSigningKeys(inst.id) });
});
