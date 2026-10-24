import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { exportResponse, parseRange } from "@/lib/audit-export";

/** Backend API: the audit log as NDJSON (`from` / `to` ISO dates optional), details decrypted, with the hash chain fields. */
export const GET = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  const u = new URL(req.url);
  return exportResponse(inst.id, parseRange(u.searchParams.get("from"), u.searchParams.get("to")), { type: "api" });
});
