import { NextResponse } from "next/server";
import { handler, errors } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { rateLimit } from "@/lib/cache";
import { retryDelivery } from "@/lib/webhooks";

/** Re-queue a delivery (for example after fixing your receiver). */
export const POST = handler(async (req: Request, { params }: { params: Promise<{ deliveryId: string }> }) => {
  const inst = await instanceFromSecretKey(req);
  if ((await rateLimit(`${inst.id}:webhook_retry`, 100, 3600)) < 0) throw errors.tooMany();
  const { deliveryId } = await params;
  await retryDelivery(inst.id, deliveryId);
  return NextResponse.json({ id: deliveryId, status: "pending" }, { status: 202 });
});
