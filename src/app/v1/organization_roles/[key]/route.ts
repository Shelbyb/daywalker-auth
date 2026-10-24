import { NextResponse } from "next/server";
import { handler, errors } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { listRoles, updateRole, deleteRole, roleUpdate } from "@/lib/auth/org-roles";

type Ctx = { params: Promise<{ key: string }> };

export const GET = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const { key } = await params;
  const r = (await listRoles(inst.id)).find((x) => x.key === key);
  if (!r) throw errors.notFound("Role not found");
  return NextResponse.json(r);
});

/** Changes apply to tokens minted from now on (within a minute for signed-in people). */
export const PATCH = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  return NextResponse.json(await updateRole(inst, (await params).key, roleUpdate.parse(await req.json()), { type: "api" }));
});

export const DELETE = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const { key } = await params;
  await deleteRole(inst, key, { type: "api" });
  return NextResponse.json({ key, deleted: true });
});
