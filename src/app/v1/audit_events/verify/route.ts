import { NextResponse } from "next/server";
import { handler, errors } from "@/lib/http";
import { rateLimit } from "@/lib/cache";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { verifyChain } from "@/lib/audit-chain";

/**
 * Backend API: recomputes the audit hash chain and reports whether any entry was edited, removed, reordered
 * or cut off. `{ ok, checked, head: { seq, hash }, problem? }`. Keep `head.hash` somewhere safe to detect a later rewrite.
 */
export const GET = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  if ((await rateLimit(`audit-verify:${inst.id}`, 10, 60)) < 0) throw errors.tooMany();
  return NextResponse.json(await verifyChain(inst.id));
});
