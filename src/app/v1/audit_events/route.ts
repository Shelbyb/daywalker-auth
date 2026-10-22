import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { listAudit } from "@/lib/audit";

/**
 * Backend API: the instance's audit log, newest first. Filters: `type`, `target` (a user ID,
 * key ID, endpoint ID...). Page with `before=<nextCursor>`. Events are kept for 90 days.
 */
export const GET = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  const u = new URL(req.url);
  const str = (k: string) => u.searchParams.get(k)?.slice(0, 100) || undefined;
  return NextResponse.json(
    await listAudit(inst.id, { type: str("type"), target: str("target"), before: str("before"), limit: Number(u.searchParams.get("limit")) || undefined }),
  );
});
