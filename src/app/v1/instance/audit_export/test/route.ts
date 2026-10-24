import { NextResponse } from "next/server";
import { handler, errors } from "@/lib/http";
import { rateLimit } from "@/lib/cache";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { testConfig } from "@/lib/audit-export";

/** Backend API: writes a small test object to your bucket to confirm the credentials work. */
export const POST = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  if ((await rateLimit(`audit-export-test:${inst.id}`, 20, 3600)) < 0) throw errors.tooMany();
  return NextResponse.json(await testConfig(inst.id));
});
