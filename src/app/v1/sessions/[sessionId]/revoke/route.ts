import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { revokeSessionById } from "@/lib/auth/sessions";

export const POST = handler(async (req: Request, { params }: { params: Promise<{ sessionId: string }> }) => {
  const inst = await instanceFromSecretKey(req);
  const { sessionId } = await params;
  await revokeSessionById(inst.id, sessionId);
  return NextResponse.json({ id: sessionId, status: "revoked" });
});
