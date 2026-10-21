import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { rotateSecret } from "@/lib/webhooks";

/** New signing secret; the old one stops working immediately. */
export const POST = handler(async (req: Request, { params }: { params: Promise<{ id: string }> }) => {
  const inst = await instanceFromSecretKey(req);
  return NextResponse.json(await rotateSecret(inst.id, (await params).id));
});
