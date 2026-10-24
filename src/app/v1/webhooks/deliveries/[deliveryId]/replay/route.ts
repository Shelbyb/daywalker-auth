import { NextResponse } from "next/server";
import { handler, errors } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { rateLimit } from "@/lib/cache";
import { replayDelivery } from "@/lib/webhooks";

/** Re-send a past delivery (any status) as a new delivery, signed with the endpoint's current secret and marked as a replay. */
export const POST = handler(async (req: Request, { params }: { params: Promise<{ deliveryId: string }> }) => {
  const inst = await instanceFromSecretKey(req);
  if ((await rateLimit(`${inst.id}:webhook_replay`, 200, 3600)) < 0) throw errors.tooMany();
  const { deliveryId } = await params;
  return NextResponse.json(await replayDelivery(inst.id, deliveryId), { status: 202 });
});
