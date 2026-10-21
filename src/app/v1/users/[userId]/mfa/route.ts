import { NextResponse } from "next/server";
import { handler, errors } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { adminResetTwoFactor } from "@/lib/auth/mfa";
import { getUser } from "@/lib/auth/users";

/** Backend API: remove a user's 2FA (they lost their device and backup codes). Verify identity first! */
export const DELETE = handler(async (req: Request, { params }: { params: Promise<{ userId: string }> }) => {
  const inst = await instanceFromSecretKey(req);
  const { userId } = await params;
  if (!(await getUser(inst.id, userId))) throw errors.notFound("User not found");
  await adminResetTwoFactor(userId);
  return NextResponse.json({ id: userId, twoFactorEnabled: false });
});
