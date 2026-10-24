import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { createForSubject, listKeys } from "@/lib/auth/api-keys";

/** Backend API: API keys of your users and organizations. Filter with ?userId= or ?orgId=. */
export const GET = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  const u = new URL(req.url).searchParams;
  return NextResponse.json({ data: await listKeys(inst, { userId: u.get("userId") ?? undefined, orgId: u.get("orgId") ?? undefined, includeRevoked: u.get("includeRevoked") === "true" }) });
});

/** Body: { name, scopes?, expiresInDays?, userId | orgId }. Returns `key` once. */
export const POST = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  return NextResponse.json(await createForSubject(inst, await req.json(), { type: "api" }), { status: 201 });
});
