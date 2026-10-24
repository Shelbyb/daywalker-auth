import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { unlockUser } from "@/lib/auth/lockout";

/** Backend API: lift a lockout now and reset its progression. `unlocked` is false when the account wasn't locked. */
export const POST = handler(async (req: Request, { params }: { params: Promise<{ userId: string }> }) => {
  const inst = await instanceFromSecretKey(req);
  const { userId } = await params;
  const unlocked = await unlockUser(inst, userId, { type: "api", reason: "admin" });
  return NextResponse.json({ id: userId, unlocked });
});
