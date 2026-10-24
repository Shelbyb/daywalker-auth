import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { cancelDeletion } from "@/lib/auth/account-deletion";

/** Backend API: stop a pending self-service deletion. `canceled` is false when none was pending. */
export const POST = handler(async (req: Request, { params }: { params: Promise<{ userId: string }> }) => {
  const inst = await instanceFromSecretKey(req);
  const { userId } = await params;
  return NextResponse.json({ id: userId, canceled: await cancelDeletion(inst, userId, { type: "api" }) });
});
