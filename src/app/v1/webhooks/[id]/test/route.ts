import { NextResponse } from "next/server";
import { handler, errors } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { rateLimit } from "@/lib/cache";
import { sendTest } from "@/lib/webhooks";

/** Sends a `webhook.test` event so you can check your receiver and signature code. */
export const POST = handler(async (req: Request, { params }: { params: Promise<{ id: string }> }) => {
  const inst = await instanceFromSecretKey(req);
  if ((await rateLimit(`${inst.id}:webhook_test`, 20, 3600)) < 0) throw errors.tooMany();
  return NextResponse.json(await sendTest(inst.id, (await params).id), { status: 202 });
});
