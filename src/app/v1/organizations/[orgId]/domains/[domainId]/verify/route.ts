import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { verifyBody, runVerify } from "@/lib/auth/org-domains";

/** `{ method: "dns" }`, `{ method: "email", mailbox }` (sends a code) or `{ method: "email", code }` (confirms it). */
export const POST = handler(async (req: Request, { params }: { params: Promise<{ orgId: string; domainId: string }> }) => {
  const inst = await instanceFromSecretKey(req);
  const { orgId, domainId } = await params;
  return NextResponse.json(await runVerify(inst, orgId, null, domainId, verifyBody.parse(await req.json())));
});
