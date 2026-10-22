import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { deleteConnection, getConnection, updateConnection } from "@/lib/auth/saml";
import { record } from "@/lib/audit";

type Ctx = { params: Promise<{ id: string }> };

export const GET = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  return NextResponse.json(await getConnection(inst.id, (await params).id));
});

export const PATCH = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const c = await updateConnection(inst.id, (await params).id, await req.json());
  void record(inst.id, "sso_connection.updated", { actor: { type: "api" }, target: c.id });
  return NextResponse.json(c);
});

export const DELETE = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const { id } = await params;
  await deleteConnection(inst.id, id);
  void record(inst.id, "sso_connection.deleted", { actor: { type: "api" }, target: id });
  return NextResponse.json({ id, deleted: true });
});
