import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { listRoles, createRole, roleInput } from "@/lib/auth/org-roles";

/** Backend API: built-in and custom organization roles with their permissions. */
export const GET = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  return NextResponse.json({ data: await listRoles(inst.id) });
});

export const POST = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  return NextResponse.json(await createRole(inst, roleInput.parse(await req.json()), { type: "api" }), { status: 201 });
});
