import { NextResponse } from "next/server";
import { handler, errors } from "@/lib/http";
import { rateLimit } from "@/lib/cache";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { pushAuditLog } from "@/lib/audit-export";

/** Backend API: push the entries not yet in your bucket now. `{ pushed, objects, lastSeq }`. */
export const POST = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  if ((await rateLimit(`audit-push-now:${inst.id}`, 12, 3600)) < 0) throw errors.tooMany();
  return NextResponse.json(await pushAuditLog(inst.id, { force: true }));
});
